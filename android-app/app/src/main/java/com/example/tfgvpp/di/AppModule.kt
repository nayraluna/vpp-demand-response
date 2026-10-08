package com.example.tfgvpp.di

import android.os.Build
import com.example.tfgvpp.BuildConfig
import com.example.tfgvpp.data.remote.VppEndpoints
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    /** 10.0.2.2 is the host loopback from the emulator; a USB device reaches 127.0.0.1 through
     *  adb reverse. Both are in the VPP certificate's SAN. */
    @Provides
    @Singleton
    fun provideVppEndpoints(): VppEndpoints {
        val host =
            if (Build.PRODUCT.contains("sdk") || Build.FINGERPRINT.contains("generic"))
                "10.0.2.2"
            else "127.0.0.1"
        // As seen from the appliance: a Pi on the LAN cannot reach a 127.0.0.1 handed over in the
        // bundle, so vpp.lan.host from local.properties (also in the SAN) when set.
        val applianceHost = BuildConfig.VPP_LAN_HOST.ifBlank { host }

        return VppEndpoints(
            baseUrl = "https://$host:8080",
            raUrl = "https://$host:8081",
            mtlsUrl = "https://$host:8443",
            defaultApplianceUrl = "http://$host:8082",
            vppUrlForAppliance = "https://$applianceHost:8080",
            vppMtlsUrlForAppliance = "https://$applianceHost:8443",
        )
    }
}
