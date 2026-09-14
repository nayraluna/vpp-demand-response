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
        val chainsToDnieRoot: Boolean, // PKIX path validation up to AC RAIZ DNIE 2
        val notExpired: Boolean,       // certificate is inside its validity window
        val proofOfPossession: Boolean,// the card signed our fresh nonce
        val tamperRejected: Boolean,   // a modified nonce must NOT verify
        val authCertPem: String,       // ready to send to the VPP later
        /** Only set when the possession proof FAILED: which certificate on the
         *  card (if any) the signature actually verifies against, per-alias
         *  key/cert details, and a cross-signing probe. Renewing the DNIe at
         *  an update point replaces keys AND certificates, and a key/cert
         *  mapping mismatch is the typical failure afterwards. */
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
        val notAfter: String,          // certificate expiry date, human-readable
    )

    /**
     * @param tag NFC tag delivered by [android.nfc.NfcAdapter.ReaderCallback].
     * @param can the 6-digit Card Access Number printed on the front of the DNIe.
     *            It opens the PACE secure channel; the PIN is asked for separately
     *            by the SDK's own dialog when the private key is used.
     * @param onCardRead invoked as soon as the certificate has been read and
     *            validated -- BEFORE any PIN interaction. This lets the UI show
     *            holder, chain and expiry even if the user cancels the PIN
     *            (useful to check expiry without knowing the PIN at all).
     *
     * Must be called off the main thread (card I/O + a blocking PIN dialog).
     */
    fun authenticate(tag: Tag, can: String, onCardRead: ((CardInfo) -> Unit)? = null): Result {
        val provider = DnieProvider()
        Security.insertProviderAt(provider, 1)
        try {
            return doAuthenticate(provider, tag, can, onCardRead)
        } finally {
            // CRITICAL: the provider sits at position 1 of the PROCESS-WIDE
            // JCA list; leaving it installed makes later generic crypto --
            // including Conscrypt's TLS handshakes -- resolve against a card
            // that is no longer on the antenna, which surfaces as
            // "Failure in SSL library ... RSA routines: internal error" in
            // every subsequent TLS connection of the app.
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

        // Everything above needed only the CAN. Report it before touching the
        // private key, which is the part that triggers the PIN dialog.
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

        // ── Proof of possession ──────────────────────────────────────────────
        // A nonce we generate right now: the card cannot have a precomputed
        // signature for it, so a valid signature proves the key is present.
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signature = sign(privateKey, provider, nonce)

        val proofOfPossession = verify(authCert, nonce, signature)
        // Negative control: flip one byte; this must NOT verify. Without it a
        // broken verify() that always returned true would look like a success.
        // NOTE: when proofOfPossession is already false this check passes
        // trivially (nothing verifies), so it only means something on success.
        val tampered = nonce.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val tamperRejected = !verify(authCert, tampered, signature)

        val diagnostic = if (proofOfPossession) null else
            buildDiagnostic(keyStore, alias, authCert, provider, nonce, signature)

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

    /**
     * Post-mortem of a failed possession proof. Answers, in order:
     *  1. WHAT is on the card: every alias with its KeyUsage, key algorithm,
     *     and issuance date (a renewal shows a recent notBefore).
     *  2. WHICH certificate the signature actually verifies against, if any --
     *     a match on a different alias means the SDK associated the selected
     *     certificate with the WRONG private key (key/cert mapping swap).
     *  3. Whether the OTHER alias's key produces a signature that verifies
     *     against the selected certificate (the swap seen from the other side).
     * All probing is best-effort: the card is already open and the PIN cached,
     * but any per-alias failure is reported instead of aborting.
     */
    private fun buildDiagnostic(
        keyStore: KeyStore, selectedAlias: String, authCert: X509Certificate,
        provider: Provider, nonce: ByteArray, signature: ByteArray,
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
            // Which digest/padding does the returned signature actually match?
            // A hit on SHA1 or PSS means the SDK signed with a different
            // scheme than the SHA256/PKCS#1 we requested (applet mismatch).
            val matching = PROBE_ALGORITHMS.filter { verifyWith(it, cert, nonce, signature) }
            appendLine("      the signature verifies with: " +
                    (matching.takeIf { it.isNotEmpty() }?.joinToString() ?: "(none)"))
            appendLine("      raw RSA probe: ${rawRsaProbe(cert, nonce, signature)}")
        }
        for (a in aliases.filter { it != selectedAlias }) {
            try {
                val otherKey = keyStore.getKey(a, null) as? PrivateKey ?: continue
                val probe = sign(otherKey, provider, nonce)
                if (verify(authCert, nonce, probe))
                    appendLine("  the KEY of [$a] matches the certificate in use (crossed key/cert mapping)")
            } catch (e: Exception) {
                appendLine("  probe with [$a]'s key: ${e.javaClass.simpleName}: ${e.message?.take(80)}")
            }
        }
    }.trimEnd()

    /**
     * The DNIe carries two certificates. They are told apart by KeyUsage:
     *   - authentication -> digitalSignature (bit 0)
     *   - qualified signature -> nonRepudiation / contentCommitment (bit 1)
     * We want the authentication one, so we require bit 0 set and bit 1 clear.
     */
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
            // TODO(TFG): revocation checking (OCSP at http://ocsp.dnie.es) — a
            // revoked (lost/stolen) DNIe still passes today; documented gap.
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

    /**
     * The decisive probe: applies the RAW RSA public-key operation of [cert]
     * to the signature and inspects the recovered block. Distinguishes the two
     * remaining failure modes when no standard algorithm verifies:
     *
     *  - the block has no PKCS#1 structure -> the signature was made by a
     *    DIFFERENT key than this certificate's (SDK/applet key-reference
     *    mismatch; only an SDK update can fix it);
     *  - the block is valid PKCS#1 and even contains the nonce's hash -> the
     *    key IS right and only the DigestInfo encoding is non-standard
     *    (fixable here, by comparing digests manually).
     */
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
            // Verification uses the PUBLIC key, so it must run on the phone, never on
            // the card. DnieProvider was inserted at position 1, so a plain
            // Signature.getInstance() would resolve to it and try to drive the card
            // for a verify operation. Pick the first provider that is not the DNIe one.
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
        // DNIe cards with RENEWED certificates emit a slightly non-standard
        // DigestInfo that strict verifiers reject even though the key, the
        // PKCS#1 padding and the SHA-256 of the data are all correct
        // (established with the raw-RSA diagnostic probe). Fall back to a
        // manual PKCS#1 v1.5 check that is strict about everything except the
        // DigestInfo's ASN.1 prefix.
        return try {
            lenientPkcs1Sha256Verify(cert, data, sig)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Manual PKCS#1 v1.5 verification, lenient ONLY about the DigestInfo
     * ASN.1 encoding: applies the raw RSA public-key operation and requires
     * a well-formed type-1 block -- 0x00 0x01, at least eight 0xFF padding
     * bytes, a 0x00 separator -- whose trailing 32 bytes equal SHA-256(data).
     * A wrong key yields a garbage block; tampered data changes the hash;
     * both fail. Only the ~19 DigestInfo prefix bytes go unparsed.
     */
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

        // X500Principal only knows the short names for a handful of attributes;
        // these are the ones the DNIe uses that would otherwise print as raw OIDs.
        val OID_NAMES = mapOf(
            "2.5.4.5" to "SERIALNUMBER",
            "2.5.4.4" to "SURNAME",
            "2.5.4.42" to "GIVENNAME",
        )
    }
}
