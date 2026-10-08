package com.example.tfgvpp.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.SharedPreferencesMigration
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.first
import javax.inject.Inject
import javax.inject.Singleton

// Migration from the SharedPreferences file older installs used, so they keep their credential.
private val Context.sessionDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "tfg_session",
    produceMigrations = { context ->
        listOf(SharedPreferencesMigration(context, "tfg-session"))
    },
)

@Singleton
class SessionStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    /** The public half of the session; the private key stays in the Keystore. */
    data class PersistedSession(
        val userCertPem: String,
        val vppCertPem: String,
        val raSerial: String,
        val enrollStatus: String,
        val holderName: String?,
        val dni: String?,
    )

    suspend fun load(): PersistedSession? {
        val p = context.sessionDataStore.data.first()
        return PersistedSession(
            userCertPem = p[USER_CERT] ?: return null,
            vppCertPem = p[VPP_CERT] ?: return null,
            raSerial = p[RA_SERIAL] ?: "?",
            enrollStatus = p[ENROLL_STATUS] ?: "restored",
            holderName = p[DNIE_HOLDER],
            dni = p[DNIE_DNI],
        )
    }

    suspend fun save(session: PersistedSession) {
        context.sessionDataStore.edit { p ->
            p[USER_CERT] = session.userCertPem
            p[VPP_CERT] = session.vppCertPem
            p[RA_SERIAL] = session.raSerial
            p[ENROLL_STATUS] = session.enrollStatus
            session.holderName?.let { p[DNIE_HOLDER] = it } ?: p.remove(DNIE_HOLDER)
            session.dni?.let { p[DNIE_DNI] = it } ?: p.remove(DNIE_DNI)
        }
    }

    /** Last appliance pairing URL (QR scan); availability declarations reuse it. */
    suspend fun applianceUrl(): String? =
        context.sessionDataStore.data.first()[APPLIANCE_URL]

    suspend fun saveApplianceUrl(url: String) {
        context.sessionDataStore.edit { it[APPLIANCE_URL] = url }
    }

    suspend fun clear() {
        context.sessionDataStore.edit { it.clear() }
    }

    private companion object {
        // Key names match the old SharedPreferences file so the migration picks them up.
        val USER_CERT = stringPreferencesKey("user_cert")
        val VPP_CERT = stringPreferencesKey("vpp_cert")
        val RA_SERIAL = stringPreferencesKey("ra_serial")
        val ENROLL_STATUS = stringPreferencesKey("enroll_status")
        val DNIE_HOLDER = stringPreferencesKey("dnie_holder")
        val DNIE_DNI = stringPreferencesKey("dnie_dni")
        val APPLIANCE_URL = stringPreferencesKey("appliance_url")
    }
}
