package com.example.tfgvpp.data.security

import android.nfc.Tag
import android.util.Base64
import es.gob.jmulticard.jse.provider.DnieLoadParameter
import es.gob.jmulticard.jse.provider.DnieProvider
import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPublicKey
import javax.security.auth.x500.X500Principal

class DnieAuth(dnieRootInput: InputStream) {

    private val dnieRoot: X509Certificate = dnieRootInput.use {
        CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
    }

    data class Result(
        val holderName: String,
        val dni: String,
        val certSubject: String,
        val certIssuer: String,
        val chainLength: Int,
        val chainsToDnieRoot: Boolean,
        val notExpired: Boolean,
        val proofOfPossession: Boolean,
        val tamperRejected: Boolean,
        val authCertPem: String,
        /** Only set when the possession proof failed: which card certificate the signature verifies against. */
        val diagnostic: String? = null,
    ) {
        val allPassed: Boolean
            get() = chainsToDnieRoot && notExpired && proofOfPossession && tamperRejected
    }

    /** What can be known from the card WITHOUT the PIN (PACE/CAN only). */
    data class CardInfo(
        val holderName: String,
        val dni: String,
        val certIssuer: String,
        val chainLength: Int,
        val chainsToDnieRoot: Boolean,
        val notExpired: Boolean,
        val notAfter: String,
    )

    /** Card read plus possession proof; [onCardRead] fires before the PIN is asked. Blocking, call off the main thread. */
    fun authenticate(tag: Tag, can: String, onCardRead: ((CardInfo) -> Unit)? = null): Result {
        val provider = DnieProvider()
        Security.insertProviderAt(provider, 1)
        try {
            return doAuthenticate(provider, tag, can, onCardRead)
        } finally {
            // Left at position 1 of the process-wide JCA list, the provider would route later
            // crypto, Conscrypt's TLS handshakes included, to a card no longer on the antenna.
            Security.removeProvider(provider.name)
        }
    }

    private fun doAuthenticate(
        provider: DnieProvider, tag: Tag, can: String, onCardRead: ((CardInfo) -> Unit)?,
    ): Result {
        val keyStore = KeyStore.getInstance("DNIeKS").apply {
            load(DnieLoadParameter.getBuilder(can, tag).build())
        }

        val alias = findAuthenticationAlias(keyStore)
            ?: error("No authentication certificate found on this card")

        val chain = (keyStore.getCertificateChain(alias) ?: emptyArray())
            .filterIsInstance<X509Certificate>()
        val authCert = chain.firstOrNull()
            ?: (keyStore.getCertificate(alias) as X509Certificate)

        val chainsToDnieRoot = validatesToDnieRoot(chain.ifEmpty { listOf(authCert) })
        val notExpired = runCatching { authCert.checkValidity() }.isSuccess
        val subject = authCert.subjectX500Principal.getName(X500Principal.RFC2253, OID_NAMES)

        // Reported before the private key is touched, which is what triggers the PIN dialog.
        onCardRead?.invoke(
            CardInfo(
                holderName = buildHolderName(subject),
                dni = rdn(subject, "SERIALNUMBER") ?: "(unknown)",
                certIssuer = authCert.issuerX500Principal.getName(X500Principal.RFC2253, OID_NAMES),
                chainLength = chain.size,
                chainsToDnieRoot = chainsToDnieRoot,
                notExpired = notExpired,
                notAfter = authCert.notAfter.toString(),
            )
        )

        val privateKey = keyStore.getKey(alias, null) as PrivateKey

        // Fresh nonce: the card cannot hold a precomputed signature for it.
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signature = sign(privateKey, provider, nonce)

        val proofOfPossession = verify(authCert, nonce, signature)
        // Negative control: a verify() that always returned true would otherwise look like success.
        val tampered = nonce.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val tamperRejected = !verify(authCert, tampered, signature)

        val diagnostic = if (proofOfPossession) null else
            buildDiagnostic(keyStore, alias, nonce, signature)

        return Result(
            holderName = buildHolderName(subject),
            dni = rdn(subject, "SERIALNUMBER") ?: "(unknown)",
            certSubject = subject,
            certIssuer = authCert.issuerX500Principal.getName(X500Principal.RFC2253, OID_NAMES),
            chainLength = chain.size,
            chainsToDnieRoot = chainsToDnieRoot,
            notExpired = notExpired,
            proofOfPossession = proofOfPossession,
            tamperRejected = tamperRejected,
            authCertPem = toPem(authCert),
            diagnostic = diagnostic,
        )
    }

    /** Post-mortem of a failed possession proof, on public material only: the card's other key
     *  is the qualified signature key and must never be driven, not even over a random nonce. */
    private fun buildDiagnostic(
        keyStore: KeyStore, selectedAlias: String,
        nonce: ByteArray, signature: ByteArray,
    ): String = buildString {
        appendLine("DIAGNOSTIC (possession proof failed):")
        val aliases = try { keyStore.aliases().toList() } catch (e: Exception) { emptyList() }
        appendLine("  aliases: $aliases")
        appendLine("  alias used: $selectedAlias")
        appendLine("  signature returned: ${signature.size} bytes")
        for (a in aliases) {
            val cert = try { keyStore.getCertificate(a) as? X509Certificate } catch (e: Exception) { null }
            if (cert == null) { appendLine("  [$a] no readable certificate"); continue }
            val ku = cert.keyUsage
            val kuText = if (ku != null && ku.size >= 2)
                "digitalSignature=${ku[0]} nonRepudiation=${ku[1]}" else "KeyUsage=?"
            val bits = (cert.publicKey as? RSAPublicKey)?.modulus?.bitLength()
            appendLine("  [$a] $kuText")
            appendLine("      key=${cert.publicKey.algorithm}${bits?.let { "-$it" } ?: ""} " +
                    "issued=${cert.notBefore} expires=${cert.notAfter}")
            // A hit on SHA1 or PSS means the SDK signed with a scheme other than the one requested.
            val matching = PROBE_ALGORITHMS.filter { verifyWith(it, cert, nonce, signature) }
            appendLine("      the signature verifies with: " +
                    (matching.takeIf { it.isNotEmpty() }?.joinToString() ?: "(none)"))
            appendLine("      raw RSA probe: ${rawRsaProbe(cert, nonce, signature)}")
        }
    }.trimEnd()

    /** Authentication cert: KeyUsage digitalSignature (bit 0) set, nonRepudiation (bit 1) clear; bit 1 marks the qualified signature cert. */
    private fun findAuthenticationAlias(keyStore: KeyStore): String? =
        keyStore.aliases().toList().firstOrNull { alias ->
            val ku = (keyStore.getCertificate(alias) as? X509Certificate)?.keyUsage
            ku != null && ku.size >= 2 && ku[0] && !ku[1]
        }

    /** Full PKIX path validation against AC RAIZ DNIE 2 as the only trust anchor. */
    private fun validatesToDnieRoot(chain: List<X509Certificate>): Boolean = try {
        // A CertPath must not contain the trust anchor itself.
        val path = chain.filterNot { it.subjectX500Principal == it.issuerX500Principal }
        val certPath = CertificateFactory.getInstance("X.509").generateCertPath(path)
        val params = PKIXParameters(setOf(TrustAnchor(dnieRoot, null))).apply {
            isRevocationEnabled = false
        }
        CertPathValidator.getInstance("PKIX").validate(certPath, params)
        true
    } catch (e: Exception) {
        false
    }

    private fun sign(key: PrivateKey, provider: Provider, data: ByteArray): ByteArray =
        Signature.getInstance(SIG_ALGORITHM, provider).apply {
            initSign(key)
            update(data)
        }.sign()

    /** Raw RSA public-key operation on the signature: no PKCS#1 block means another key signed;
     *  the nonce's hash inside the block means only the DigestInfo encoding is non-standard. */
    private fun rawRsaProbe(
        cert: X509Certificate, nonce: ByteArray, signature: ByteArray,
    ): String = try {
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, cert.publicKey)
        val m = cipher.doFinal(signature)
        if (m.size < 11 || m[0] != 0x00.toByte() || m[1] != 0x01.toByte()) {
            "no PKCS#1 structure: the signature does NOT come from this certificate's key"
        } else {
            val digests = listOf("SHA-256", "SHA-1", "SHA-384", "SHA-512").associateWith {
                java.security.MessageDigest.getInstance(it).digest(nonce)
            }
            val hit = digests.entries.firstOrNull { (_, h) ->
                m.size >= h.size &&
                    m.copyOfRange(m.size - h.size, m.size).contentEquals(h)
            }
            when {
                hit != null ->
                    "key CORRECT: valid PKCS#1 with the nonce's ${hit.key} present " +
                        "(non-standard DigestInfo; fixable in the app)"
                else ->
                    "key CORRECT (PKCS#1 structure) but the hash is NOT the nonce's " +
                        "(the SDK signed different data)"
            }
        }
    } catch (e: Exception) {
        "not runnable: ${e.javaClass.simpleName}"
    }

    /** [verify] with an explicit algorithm, for the diagnostic probe matrix. */
    private fun verifyWith(
        algorithm: String, cert: X509Certificate, data: ByteArray, sig: ByteArray,
    ): Boolean = try {
        val soft = Security.getProviders("Signature.$algorithm")
            ?.firstOrNull { it !is DnieProvider }
        val engine = if (soft != null) Signature.getInstance(algorithm, soft)
        else Signature.getInstance(algorithm)
        engine.apply {
            initVerify(cert.publicKey)
            update(data)
        }.verify(sig)
    } catch (e: Exception) {
        false
    }

    private fun verify(cert: X509Certificate, data: ByteArray, sig: ByteArray): Boolean {
        val strict = try {
            // Public-key verification must run on the phone: with DnieProvider at position 1 a
            // plain getInstance() would resolve to it and try to drive the card.
            val soft = Security.getProviders("Signature.$SIG_ALGORITHM")
                ?.firstOrNull { it !is DnieProvider }
            val engine = if (soft != null) Signature.getInstance(SIG_ALGORITHM, soft)
            else Signature.getInstance(SIG_ALGORITHM)

            engine.apply {
                initVerify(cert.publicKey)
                update(data)
            }.verify(sig)
        } catch (e: Exception) {
            false
        }
        if (strict) return true
        // Renewed DNIe certificates emit a non-standard DigestInfo that strict verifiers reject
        // although key, padding and hash are right; fall back to a check lenient only there.
        return try {
            lenientPkcs1Sha256Verify(cert, data, sig)
        } catch (e: Exception) {
            false
        }
    }

    /** PKCS#1 v1.5 check lenient only about the DigestInfo prefix: a wrong key or tampered data still fail. */
    private fun lenientPkcs1Sha256Verify(
        cert: X509Certificate, data: ByteArray, sig: ByteArray,
    ): Boolean {
        val cipher = javax.crypto.Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, cert.publicKey)
        val m = cipher.doFinal(sig)
        if (m.size < 11 || m[0] != 0x00.toByte() || m[1] != 0x01.toByte()) return false
        var i = 2
        while (i < m.size && m[i] == 0xFF.toByte()) i++
        if (i < 10 || i >= m.size || m[i] != 0x00.toByte()) return false
        val digestInfo = m.copyOfRange(i + 1, m.size)
        val hash = java.security.MessageDigest.getInstance("SHA-256").digest(data)
        if (digestInfo.size < hash.size) return false
        return digestInfo.copyOfRange(digestInfo.size - hash.size, digestInfo.size)
            .contentEquals(hash)
    }

    private fun buildHolderName(subject: String): String {
        val given = rdn(subject, "GIVENNAME")
        val surname = rdn(subject, "SURNAME")
        return listOfNotNull(given, surname).joinToString(" ").ifBlank {
            rdn(subject, "CN") ?: "(unknown)"
        }
    }

    private fun rdn(dn: String, key: String): String? =
        Regex("(?:^|,)\\s*$key=([^,]+)").find(dn)?.groupValues?.get(1)?.trim()

    private fun toPem(cert: X509Certificate): String = buildString {
        append("-----BEGIN CERTIFICATE-----\n")
        append(Base64.encodeToString(cert.encoded, Base64.NO_WRAP).chunked(64).joinToString("\n"))
        append("\n-----END CERTIFICATE-----\n")
    }

    private companion object {
        const val SIG_ALGORITHM = "SHA256withRSA" // DNIe keys are RSA

        /** Verification matrix for the possession-failure diagnostic. */
        val PROBE_ALGORITHMS = listOf(
            "SHA256withRSA", "SHA1withRSA", "SHA384withRSA", "SHA512withRSA",
            "SHA256withRSA/PSS",
        )

        // X500Principal would print these DNIe attributes as raw OIDs.
        val OID_NAMES = mapOf(
            "2.5.4.5" to "SERIALNUMBER",
            "2.5.4.4" to "SURNAME",
            "2.5.4.42" to "GIVENNAME",
        )
    }
}
