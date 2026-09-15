package com.example.tfgvpp.data.remote.vpp

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.JSONObjectUtils
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.TlsVersion
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemWriter
import java.io.InputStream
import java.io.StringWriter
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

class RegistrationClient(caInput: InputStream) {

    private val caCertificate: X509Certificate
    private val http: OkHttpClient
    private val jsonType = "application/json".toMediaType()

    init {
        val bytes = caInput.use { it.readBytes() }
        caCertificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as X509Certificate
        http = buildServerAuthClient(caCertificate)
    }

    /** The user's platform credential: software key pair + RA-issued certificate. */
    class UserCredential(
        val privateKey: PrivateKey,
        val certificate: X509Certificate,
        val certificatePem: String,
    ) {
        /** RFC 2253 subject; for a CN-only subject it matches the server's rfc4514 form. */
        val subject: String
            get() = certificate.subjectX500Principal.getName(X500Principal.RFC2253)
    }

    data class Registration(
        val credential: UserCredential,
        val subject: String,
        val raSerial: String,
        val userCertChainsToRa: Boolean,
        val enrollStatus: String,       // "enrolled" | "already-enrolled"
        val vppCertificatePem: String,
        val vppCertChainsToRa: Boolean,
    ) {
        val allPassed: Boolean
            get() = userCertChainsToRa && vppCertChainsToRa &&
                    (enrollStatus == "enrolled" || enrollStatus == "already-enrolled")
    }

    /**
     * Runs the two exchanges of user registration against the live services.
     *
     * @param commonName subject CN the RA will certify (e.g. "android-3f9c21").
     * @param raUrl      CA base URL, registration authority side (port 8081).
     * @param vppUrl     VPP server-authenticated base URL (port 8080).
     * @param keyPair    the user's key pair. On the phone it is generated
     *                   inside the Android Keystore (CredentialStore), so the
     *                   private key is non-exportable; the default software
     *                   key keeps this class runnable on the plain JVM.
     */
    fun register(
        commonName: String, raUrl: String, vppUrl: String,
        keyPair: KeyPair = softwareKeyPair(),
    ): Registration {
        // PKCS#10 CSR: public key + subject + self-signature (proof of
        // possession). The signer resolves the JCA provider from the key, so
        // it works for both software and Android Keystore private keys; the
        // algorithm follows the key type (EC on the phone, RSA on the JVM).
        val csrAlgorithm =
            if (keyPair.private.algorithm == "EC") "SHA256withECDSA" else "SHA256withRSA"
        val csr = JcaPKCS10CertificationRequestBuilder(
            X500Name("CN=$commonName"), keyPair.public
        ).build(JcaContentSignerBuilder(csrAlgorithm).build(keyPair.private))
        val csrPem = toPem("CERTIFICATE REQUEST", csr.encoded)

        val issue = postJson("$raUrl/ra/issue", mapOf("csr" to csrPem))
        val certPem = issue["certificate"] as String
        val userCert = CertificateFactory.getInstance("X.509")
            .generateCertificate(certPem.byteInputStream()) as X509Certificate
        val credential = UserCredential(keyPair.private, userCert, certPem)

        // Enroll at the VPP with the issued certificate; keep the returned
        // Cert_VPP -- the pairing bundle delivers it to the appliance later.
        val enroll = postJson("$vppUrl/enroll", mapOf("certificate" to certPem))
        val vppCertPem = enroll["vpp_certificate"] as String
        val vppCert = CertificateFactory.getInstance("X.509")
            .generateCertificate(vppCertPem.byteInputStream()) as X509Certificate

        return Registration(
            credential = credential,
            subject = credential.subject,
            raSerial = issue["serial"] as? String ?: "?",
            userCertChainsToRa = chainsToRa(userCert),
            enrollStatus = enroll["status"] as String,
            vppCertificatePem = vppCertPem,
            vppCertChainsToRa = chainsToRa(vppCert),
        )
    }

    private fun chainsToRa(cert: X509Certificate): Boolean =
        try { cert.verify(caCertificate.publicKey); true } catch (e: Exception) { false }

    private fun postJson(url: String, body: Map<String, Any>): Map<String, Any> {
        val req = Request.Builder().url(url)
            .post(JSONObjectUtils.toJSONString(body).toRequestBody(jsonType))
            .build()
        http.newCall(req).execute().use { resp ->
            val text = resp.body!!.string()
            check(resp.isSuccessful) { "HTTP ${resp.code} $url -> ${text.take(200)}" }
            return JSONObjectUtils.parse(text)
        }
    }

    companion object {
        /** OkHttp client that trusts ONLY the RA/CA (the only trust anchor everywhere). */
        fun buildServerAuthClient(caCertificate: X509Certificate): OkHttpClient {
            val tm = trustManagerFor(caCertificate)
            val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), null) }
            return OkHttpClient.Builder().sslSocketFactory(ssl.socketFactory, tm).build()
        }

        fun trustManagerFor(caCertificate: X509Certificate): X509TrustManager {
            val ks = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("tfg-ra", caCertificate)
            }
            val tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            ).apply { init(ks) }
            return tmf.trustManagers[0] as X509TrustManager
        }

        fun toPem(type: String, der: ByteArray): String {
            val out = StringWriter()
            PemWriter(out).use { it.writeObject(PemObject(type, der)) }
            return out.toString()
        }

        /** OkHttp client that AUTHENTICATES with the credential (mutual TLS).
         *
         * The credential is presented through a key manager rather than an
         * in-memory PKCS#12 store: an Android Keystore private key is
         * non-exportable -- it can be USED to sign the handshake, but never
         * serialised into a store -- so the key must be used in place.
         *
         * The channel stays pinned to TLS 1.2. The pin predates the EC
         * credential (TLS 1.3 mandates RSA-PSS for the client's
         * CertificateVerify, which some Keymasters fail with RSA Keystore
         * keys); with ECDSA 1.3 would likely negotiate fine, but every
         * end-to-end validation on real hardware ran over 1.2, so unpinning
         * is deliberately left untested. */
        fun buildMutualTlsClient(
            credential: UserCredential, caCertificate: X509Certificate,
        ): OkHttpClient {
            val tm = trustManagerFor(caCertificate)
            val km = CredentialKeyManager(credential)
            val ssl = SSLContext.getInstance("TLS")
                .apply { init(arrayOf(km), arrayOf(tm), null) }
            val tls12 = ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
                .tlsVersions(TlsVersion.TLS_1_2)
                .build()
            return OkHttpClient.Builder()
                .sslSocketFactory(ssl.socketFactory, tm)
                .connectionSpecs(listOf(tls12))
                .build()
        }

        /** 2048-bit RSA software key, matching the platform PKI (JVM tests). */
        fun softwareKeyPair(): KeyPair =
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

        /** Compact JWS signed with the credential, its certificate in the x5c
         *  header. ES256 for EC credentials (the phone's Keystore key), RS256
         *  for RSA ones (the JVM tests' software keys); the platform verifies
         *  both. */
        fun signedJws(credential: UserCredential, claims: Map<String, Any>): String {
            val isEc = credential.privateKey.algorithm == "EC"
            val algorithm = if (isEc) JWSAlgorithm.ES256 else JWSAlgorithm.RS256
            val signer = if (isEc) ECDSASigner(credential.privateKey, Curve.P_256)
            else RSASSASigner(credential.privateKey)
            return JWSObject(
                JWSHeader.Builder(algorithm)
                    .x509CertChain(listOf(Base64.encode(credential.certificate.encoded)))
                    .build(),
                Payload(claims),
            ).apply { sign(signer) }.serialize()
        }
    }

    /** Presents the credential on the TLS handshake, using the key in place. */
    private class CredentialKeyManager(
        private val credential: UserCredential,
    ) : X509ExtendedKeyManager() {
        private val alias = "user"

        override fun chooseClientAlias(
            keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?,
        ): String = alias

        override fun chooseEngineClientAlias(
            keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?,
        ): String = alias

        override fun getClientAliases(
            keyType: String?, issuers: Array<out Principal>?,
        ): Array<String> = arrayOf(alias)

        override fun getCertificateChain(alias: String?) = arrayOf(credential.certificate)

        // Keystore-backed keys travel wrapped so Conscrypt signs them through
        // the JCA path instead of the native keystore engine, broken on some
        // vendor ROMs (see TlsKeyDelegation); software keys pass untouched.
        override fun getPrivateKey(alias: String?): PrivateKey =
            TlsKeyDelegation.forTls(credential.privateKey)

        override fun getServerAliases(
            keyType: String?, issuers: Array<out Principal>?,
        ): Array<String>? = null

        override fun chooseServerAlias(
            keyType: String?, issuers: Array<out Principal>?, socket: Socket?,
        ): String? = null
    }
}
