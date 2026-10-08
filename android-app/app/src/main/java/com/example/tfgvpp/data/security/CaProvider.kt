package com.example.tfgvpp.data.security

import android.content.Context
import com.example.tfgvpp.R
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CaProvider @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val bytes: ByteArray =
        context.resources.openRawResource(R.raw.ca).use { it.readBytes() }

    val certificate: X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as X509Certificate

    fun newInputStream(): InputStream = ByteArrayInputStream(bytes)
}
