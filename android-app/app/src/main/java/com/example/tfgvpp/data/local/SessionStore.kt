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

// Migrates from the SharedPreferences file older versions of the app used, so
// an existing install keeps its credential across the update.
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
    /** The persisted public half of the session. */
    data class PersistedSession(
        val userCertPem: String,
        val vppCertPem: String,
        val raSerial: String,
        val enrollStatus: String,
        val holderName: String?,
        val dni: String?,
    )

    /** The stored session, or null if nothing was persisted. */
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

    /** Persists the session's public material after a successful registration. */
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

    /** Remembers the appliance URL the user last paired against. */
    suspend fun saveApplianceUrl(url: String) {
        context.sessionDataStore.edit { it[APPLIANCE_URL] = url }
    }

    /** Forgets everything (logout). */
    suspend fun clear() {
        context.sessionDataStore.edit { it.clear() }
    }

    private companion object {
        // Key names match the old SharedPreferences file, so the DataStore
        // migration picks existing values up unchanged.
        val USER_CERT = stringPreferencesKey("user_cert")
        val VPP_CERT = stringPreferencesKey("vpp_cert")
        val RA_SERIAL = stringPreferencesKey("ra_serial")
        val ENROLL_STATUS = stringPreferencesKey("enroll_status")
        val DNIE_HOLDER = stringPreferencesKey("dnie_holder")
        val DNIE_DNI = stringPreferencesKey("dnie_dni")
        val APPLIANCE_URL = stringPreferencesKey("appliance_url")
    }
}
