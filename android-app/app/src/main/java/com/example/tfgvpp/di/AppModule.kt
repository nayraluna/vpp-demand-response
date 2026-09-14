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

    /**
     * Emulator: 10.0.2.2 is the host's loopback as seen from inside the
     * emulator. Physical device over USB: 127.0.0.1 works through
     * `adb reverse` (recreated on install by the `adbReverseVpp` task). Both
     * addresses are in the VPP certificate's SAN. (For a cable-free demo over
     * Wi-Fi, use the PC's LAN IP instead -- also in the SAN -- and open the
     * Windows firewall.)
     */
    @Provides
    @Singleton
    fun provideVppEndpoints(): VppEndpoints {
        val host =
            if (Build.PRODUCT.contains("sdk") || Build.FINGERPRINT.contains("generic"))
                "10.0.2.2"
            else "127.0.0.1"
        // URLs as seen FROM THE APPLIANCE, which the app hands over during
        // pairing. A Raspberry Pi on the home network could never reach a
        // 127.0.0.1 handed to it in the bundle, so this must be the PC's LAN
        // address -- configured in local.properties as `vpp.lan.host` and added
        // to the certificate SAN via EXTRA_SAN_IPS. When unset it falls back to
        // the host the app uses itself, which is correct for an emulator or a
        // USB-tethered appliance running on the same PC.
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
