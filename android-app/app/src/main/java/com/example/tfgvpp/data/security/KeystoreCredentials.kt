package com.example.tfgvpp.data.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.spec.ECGenParameterSpec
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KeystoreCredentials @Inject constructor() {

    /** New EC P-256 key pair inside the Android Keystore (replaces any
     *  previous one under the same alias; the RA refuses re-enrolling an old
     *  key anyway).
     *
     *  EC instead of RSA on purpose: TLS client authentication with Keystore
     *  RSA keys proved unusable on some vendor TEEs -- the native keystore
     *  engine fails, TLS negotiates PSS even on 1.2, and the KeyMint refuses
     *  the raw operation (INCOMPATIBLE_PADDING_MODE) that would serve it.
     *  ECDSA has none of those failure modes and is the best-exercised
     *  Keystore path across devices. The user's artefacts are then signed
     *  ES256 (the platform accepts ES256 and RS256 alike).
     *
     *  Digests: SHA256 for CSR/JWS (hashed inside the Keystore); NONE for the
     *  TLS handshake, where Conscrypt pre-hashes and requests a raw ECDSA
     *  signature. */
    fun generateKeyPair(): KeyPair {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(
            KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_NONE)
                .build())
        return generator.generateKeyPair()
    }

    /** The persisted private key, or null if the Keystore entry is gone. */
    fun loadPrivateKey(): PrivateKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
    }

    /** Deletes the Keystore entry (logout). */
    fun clear() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }


    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "tfg-user-credential"
    }
}
