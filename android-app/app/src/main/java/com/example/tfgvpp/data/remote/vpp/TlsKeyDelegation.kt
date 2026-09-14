package com.example.tfgvpp.data.remote.vpp

import java.security.InvalidKeyException
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.SignatureSpi

class OpaquePrivateKey(internal val delegate: PrivateKey) : PrivateKey {
    override fun getAlgorithm(): String = delegate.algorithm

    /** null on purpose: prevents any provider from converting the key. */
    override fun getFormat(): String? = null

    /** null on purpose: the key material is non-exportable anyway. */
    override fun getEncoded(): ByteArray? = null
}

/** Signs by delegating to the wrapped key's own JCA provider. */
abstract class DelegatingSignatureSpi(private val algorithm: String) : SignatureSpi() {

    private var inner: Signature? = null

    override fun engineInitSign(privateKey: PrivateKey) {
        val opaque = privateKey as? OpaquePrivateKey
            ?: throw InvalidKeyException("only OpaquePrivateKey is supported")
        inner = Signature.getInstance(algorithm).apply { initSign(opaque.delegate) }
    }

    override fun engineInitVerify(publicKey: PublicKey): Unit =
        throw InvalidKeyException("sign-only delegation")

    override fun engineUpdate(b: Byte) {
        requireNotNull(inner).update(b)
    }

    override fun engineUpdate(b: ByteArray, off: Int, len: Int) {
        requireNotNull(inner).update(b, off, len)
    }

    override fun engineSign(): ByteArray = requireNotNull(inner).sign()

    override fun engineVerify(sigBytes: ByteArray): Boolean =
        throw java.security.SignatureException("sign-only delegation")

    @Deprecated("Deprecated in Java")
    override fun engineSetParameter(param: String, value: Any?): Unit =
        throw UnsupportedOperationException()

    @Deprecated("Deprecated in Java")
    override fun engineGetParameter(param: String): Any =
        throw UnsupportedOperationException()

    // Public concrete classes: JCA instantiates SPIs by class name.
    class NoneWithEcdsa : DelegatingSignatureSpi("NONEwithECDSA")
    class Sha256WithEcdsa : DelegatingSignatureSpi("SHA256withECDSA")
    class Sha384WithEcdsa : DelegatingSignatureSpi("SHA384withECDSA")
    class Sha512WithEcdsa : DelegatingSignatureSpi("SHA512withECDSA")
}

object TlsKeyDelegation {

    @Suppress("DEPRECATION") // (String, Double, String) ctor: the String-version needs API 28
    private val provider = object : Provider(
        "TfgTlsDelegation", 1.0,
        "JCA delegation for opaque Keystore-backed TLS client keys",
    ) {
        init {
            put("Signature.NONEwithECDSA", DelegatingSignatureSpi.NoneWithEcdsa::class.java.name)
            put("Signature.SHA256withECDSA", DelegatingSignatureSpi.Sha256WithEcdsa::class.java.name)
            put("Signature.SHA384withECDSA", DelegatingSignatureSpi.Sha384WithEcdsa::class.java.name)
            put("Signature.SHA512withECDSA", DelegatingSignatureSpi.Sha512WithEcdsa::class.java.name)
        }
    }

    /**
     * Wraps hardware-backed Android Keystore keys for TLS use; any other key
     * (e.g. the JVM flow test's software keys) is returned untouched. The
     * delegation provider is appended at the END of the provider list -- it
     * only ever accepts [OpaquePrivateKey], so it cannot interfere with
     * anything else (lesson learned from the DNIe provider incident).
     */
    fun forTls(key: PrivateKey): PrivateKey {
        if (!key.javaClass.name.startsWith("android.security.keystore")) return key
        if (Security.getProvider(provider.name) == null) Security.addProvider(provider)
        return OpaquePrivateKey(key)
    }
}
