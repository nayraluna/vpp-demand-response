package com.example.tfgvpp.data.remote.vpp

import com.nimbusds.jose.util.JSONObjectUtils
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.InputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class OperationalClient(caInput: InputStream, registration: RegistrationClient.Registration) {

    private val credential = registration.credential
    private val caCertificate: X509Certificate = caInput.use {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(it) as X509Certificate
    }
    private val mtls = RegistrationClient.buildMutualTlsClient(credential, caCertificate)
    private val jsonType = "application/json".toMediaType()

    data class ApplianceInfo(
        val ven: String,
        val nominalPower: Long,
        val maxCurtail: Long,
        val recovery: Long,
        val availability: Map<String, String>?, // day -> 48-slot bitmap, null if undeclared
        val version: Long?,
        val updatedAt: String?,
    )

    fun myAppliances(mtlsUrl: String): List<ApplianceInfo> {
        val json = getJson("$mtlsUrl/availability")
        @Suppress("UNCHECKED_CAST")
        val appliances = json["appliances"] as? List<Map<String, Any?>> ?: emptyList()
        return appliances.map { a ->
            @Suppress("UNCHECKED_CAST")
            val slots = a["availability"] as? Map<String, String>
            ApplianceInfo(
                ven = a["ven_subject"] as String,
                nominalPower = (a["nominal_power"] as Number).toLong(),
                maxCurtail = (a["max_curtail"] as Number).toLong(),
                recovery = (a["recovery"] as Number).toLong(),
                availability = slots,
                version = (a["version"] as? Number)?.toLong(),
                updatedAt = a["updated_at"] as? String,
            )
        }
    }

    data class DeclareResult(
        val ven: String,
        val declaredSlots: Long,
        val vppStatus: String,
        val version: Long,
    )

    /** Owner-signed, versioned calendar: the appliance adopts only a newer version, so an old one cannot
     *  be replayed. The version derives from the VPP's stored state, not a phone counter, so a reinstall
     *  or a slow clock cannot produce a stale one. */
    fun declareAvailability(
        mtlsUrl: String, ven: String, slots: Map<String, String>,
    ): DeclareResult {
        val stored = myAppliances(mtlsUrl).find { it.ven == ven }?.version ?: 0L
        val version = maxOf(stored + 1, System.currentTimeMillis())
        val jws = RegistrationClient.signedJws(credential,
            mapOf("slots" to slots, "version" to version))
        val vpp = postJson(mtls, "$mtlsUrl/availability",
            mapOf("ven" to ven, "jws" to jws))
        return DeclareResult(
            ven = ven,
            declaredSlots = (vpp["declared_slots"] as Number).toLong(),
            vppStatus = vpp["status"] as String,
            version = (vpp["version"] as Number).toLong(),
        )
    }

    data class Participation(
        val activationId: String,
        val ven: String,
        val day: String,
        val interval: String,     // "15:00-17:00"
        val action: String,       // "reduce" | "shutdown"
        val reductionPct: Long,
        val energyKwh: Double,
        val rewardEur: Double,
        val executedAt: String,
    )

    data class ParticipationSummary(
        val participations: List<Participation>,
        val count: Long,
        val totalEnergyKwh: Double,
        val totalRewardEur: Double,
        val priceEurPerKwh: Double,
    )

    fun participation(mtlsUrl: String): ParticipationSummary {
        val json = getJson("$mtlsUrl/participation")
        @Suppress("UNCHECKED_CAST")
        val records = json["participations"] as? List<Map<String, Any?>> ?: emptyList()
        return ParticipationSummary(
            participations = records.map { p ->
                Participation(
                    activationId = p["activation_id"] as String,
                    ven = p["ven_subject"] as String,
                    day = p["day"] as String,
                    interval = p["interval"] as String,
                    action = p["action"] as String,
                    reductionPct = (p["reduction_pct"] as Number).toLong(),
                    energyKwh = (p["energy_kwh"] as Number).toDouble(),
                    rewardEur = (p["reward_eur"] as Number).toDouble(),
                    executedAt = p["executed_at"] as String,
                )
            },
            count = (json["count"] as Number).toLong(),
            totalEnergyKwh = (json["total_energy_kwh"] as Number).toDouble(),
            totalRewardEur = (json["total_reward_eur"] as Number).toDouble(),
            priceEurPerKwh = (json["price_eur_per_kwh"] as Number).toDouble(),
        )
    }

    private fun getJson(url: String): Map<String, Any> {
        val req = Request.Builder().url(url).build()
        mtls.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} $url -> ${text.take(200)}" }
            return JSONObjectUtils.parse(text)
        }
    }

    private fun postJson(client: OkHttpClient, url: String, body: Map<String, Any>): Map<String, Any> {
        val req = Request.Builder().url(url)
            .post(JSONObjectUtils.toJSONString(body).toRequestBody(jsonType)).build()
        client.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} $url -> ${text.take(200)}" }
            return JSONObjectUtils.parse(text)
        }
    }

    companion object {
        val DAYS = listOf("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        const val SLOTS_PER_DAY = 48 // 30-minute slots

        /** '1' between [fromHour, toHour) on the given days, '0' elsewhere. */
        fun weeklySlots(days: Set<String>, fromHour: Int, toHour: Int): Map<String, String> {
            require(fromHour in 0..23 && toHour in 1..24 && fromHour < toHour) {
                "invalid hour range $fromHour..$toHour"
            }
            val from = fromHour * 2
            val to = toHour * 2
            return DAYS.associateWith { day ->
                if (day in days)
                    "0".repeat(from) + "1".repeat(to - from) + "0".repeat(SLOTS_PER_DAY - to)
                else "0".repeat(SLOTS_PER_DAY)
            }
        }
    }
}
