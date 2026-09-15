package com.example.tfgvpp.data.remote.appliance

import com.example.tfgvpp.data.remote.vpp.RegistrationClient
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.util.JSONObjectUtils
import org.bouncycastle.asn1.ASN1String
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal

class PairingClient(caInput: InputStream, private val registration: RegistrationClient.Registration) {

    private val caCertificate: X509Certificate
    private val caPem: String
    private val jsonType = "application/json".toMediaType()

    /** Plain client for the appliance's local pairing service (HTTP, home network). */
    private val local = OkHttpClient()

    /** Mutual-TLS client for the VPP: presents the user's RA-issued certificate. */
    private val mtls: OkHttpClient

    init {
        val bytes = caInput.use { it.readBytes() }
        caCertificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as X509Certificate
        caPem = RegistrationClient.toPem("CERTIFICATE", caCertificate.encoded)
        mtls = RegistrationClient.buildMutualTlsClient(registration.credential, caCertificate)
    }

    data class PairResult(
        val status: String,               // "paired"
        val venSubject: String,           // from the owner proof's x5c certificate
        val owner: String,                // who the appliance recorded as its owner
        val parameters: Map<String, Long>,// P (W), max (min), rec (min), from the proof
        val ownerProof: String,           // compact JWS, signed inside the HSM
        val proofSignatureValid: Boolean,
        val proofCertChainsToRa: Boolean,
        val proofOwnerMatches: Boolean,   // proof.owner == our certificate subject
        val powerMatchesCertified: Boolean, // proof.P == OU=P=<W> in the VEN cert
    ) {
        val allPassed: Boolean
            get() = status == "paired" && proofSignatureValid && proofCertChainsToRa &&
                    proofOwnerMatches && powerMatchesCertified
    }

    data class BindResult(val status: String, val ven: String, val owner: String)

    /**
     * @param applianceUrl          the appliance's local pairing service (port 8082).
     * @param vppUrlForAppliance    VPP bootstrap URL as seen FROM THE APPLIANCE
     *                              (it runs on the PC, so its loopback -- not the
     *                              phone's view of the same service).
     * @param vppMtlsUrlForAppliance idem for the mutually authenticated endpoint.
     */
    fun pair(
        applianceUrl: String,
        vppUrlForAppliance: String,
        vppMtlsUrlForAppliance: String,
    ): PairResult {
        // The bundle: what the appliance needs in order to operate. Signing it
        // with the user's key is what tells the appliance, in an authenticated
        // way, WHO is enrolling it (the identity the owner proof will bind).
        val payload = mapOf(
            "vpp_url" to vppUrlForAppliance,
            "vpp_mtls_url" to vppMtlsUrlForAppliance,
            "cert_vpp" to registration.vppCertificatePem,
            "cert_ra" to caPem,
        )
        val bundle = RegistrationClient.signedJws(registration.credential, payload)

        val body = JSONObjectUtils.toJSONString(mapOf("jws" to bundle))
            .toRequestBody(jsonType)
        val req = Request.Builder().url("$applianceUrl/pair").post(body).build()
        val resp = local.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} $applianceUrl/pair -> ${text.take(200)}" }
            JSONObjectUtils.parse(text)
        }

        return verifyProof(
            status = resp["status"] as String,
            owner = resp["owner"] as String,
            ownerProof = resp["owner_proof"] as String,
        )
    }

    /** Local verification of the owner proof: the same checks the VPP repeats. */
    private fun verifyProof(
        status: String, owner: String, ownerProof: String,
    ): PairResult {
        val jws = JWSObject.parse(ownerProof)
        val venCert = CertificateFactory.getInstance("X.509").generateCertificate(
            jws.header.x509CertChain.first().decode().inputStream()
        ) as X509Certificate

        val signatureValid = (venCert.publicKey as? RSAPublicKey)
            ?.let { jws.verify(RSASSAVerifier(it)) } ?: false
        val chainsToRa =
            try { venCert.verify(caCertificate.publicKey); true } catch (e: Exception) { false }

        val claims = jws.payload.toJSONObject()
        val ownerMatches = claims["owner"] == registration.credential.subject

        // The parameters are read from the SIGNED payload, never from the plain
        // fields of the pairing response: the local channel has no integrity
        // protection, only the artefacts it carries do.
        val parameters = listOf("P", "max", "rec")
            .associateWith { (claims[it] as Number).toLong() }

        // The CA certifies the nominal power inside the VEN certificate
        // (OU=P=<watts>); the proof must declare the same value. The OU is read
        // from the ASN.1 name directly: string forms escape the inner '='.
        val venSubject = venCert.subjectX500Principal.getName(X500Principal.RFC2253)
        val certifiedPower = X500Name.getInstance(venCert.subjectX500Principal.encoded)
            .getRDNs(BCStyle.OU)
            .mapNotNull { (it.first.value as? ASN1String)?.string }
            .firstOrNull { it.startsWith("P=") }
            ?.removePrefix("P=")?.toLongOrNull()
        val powerMatches = certifiedPower != null &&
                (claims["P"] as? Number)?.toLong() == certifiedPower

        return PairResult(
            status, venSubject, owner, parameters, ownerProof,
            proofSignatureValid = signatureValid,
            proofCertChainsToRa = chainsToRa,
            proofOwnerMatches = ownerMatches,
            powerMatchesCertified = powerMatches,
        )
    }

    /** Step 8c: deliver the owner proof to the VPP over the mTLS channel. */
    fun forwardOwnerProof(vppMtlsUrl: String, ownerProof: String): BindResult {
        val body = JSONObjectUtils.toJSONString(mapOf("owner_proof" to ownerProof))
            .toRequestBody(jsonType)
        val req = Request.Builder().url("$vppMtlsUrl/appliances/owner-proof").post(body).build()
        mtls.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} /appliances/owner-proof -> ${text.take(200)}" }
            val json = JSONObjectUtils.parse(text)
            return BindResult(
                status = json["status"] as String,
                ven = json["ven"] as String,
                owner = json["owner"] as String,
            )
        }
    }

    /** Sanity check of the mutual-TLS channel: who does the VPP think we are? */
    fun session(vppMtlsUrl: String): String {
        val req = Request.Builder().url("$vppMtlsUrl/session").build()
        mtls.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} /session -> ${text.take(200)}" }
            return text
        }
    }

    companion object {
        /** Returns the appliance to state 0 so pairing can be exercised again. */
        fun factoryReset(applianceUrl: String): String {
            val req = Request.Builder().url("$applianceUrl/factory-reset")
                .post(ByteArray(0).toRequestBody(null)).build()
            OkHttpClient().newCall(req).execute().use { r ->
                val text = r.body!!.string()
                check(r.isSuccessful) { "HTTP ${r.code} /factory-reset -> ${text.take(200)}" }
                return text
            }
        }
    }
}
