package com.example.tfgvpp

import ar.com.hjg.pngj.PngReaderInt
import com.example.tfgvpp.data.remote.appliance.PairingClient
import com.example.tfgvpp.data.remote.vpp.OperationalClient
import com.example.tfgvpp.data.remote.vpp.RegistrationClient
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.nimbusds.jose.util.JSONObjectUtils
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.net.Socket
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.ZoneOffset
import java.time.ZonedDateTime

class RegistrationFlowTest {

    // Gradle runs unit tests from the module directory; -Dtfg.repo overrides.
    private val repoDir = File(System.getProperty("tfg.repo") ?: "../..")
    private val certsDir = File(repoDir, "certs")
    private val caFile = File(certsDir, "CA.crt")
    private val python = File(repoDir, ".venv/Scripts/python.exe")

    // 127.0.0.1, not localhost: on Windows the name resolves to ::1 first and pays a ~2 s fallback.
    private val vppUrl = "https://127.0.0.1:8080"
    private val raUrl = "https://127.0.0.1:8081"
    private val applianceUrl = "http://127.0.0.1:8082"
    private val mtlsUrl = "https://127.0.0.1:8443"

    private val jsonType = "application/json".toMediaType()

    @Before
    fun requireLiveServices() {
        assumeTrue("CA.crt not found at $caFile", caFile.isFile)
        assumeTrue("venv python not found at $python", python.isFile)
        for (port in intArrayOf(8080, 8081, 8082, 8443)) {
            assumeTrue("service on :$port is not running",
                runCatching { Socket("127.0.0.1", port).close() }.isSuccess)
        }
    }

    @Test
    fun fullRegistrationAndOperationalFlow() {
        // A paired appliance refuses to pair again.
        PairingClient.factoryReset(applianceUrl)

        val cn = "test-android-" + ByteArray(4).let {
            SecureRandom().nextBytes(it); it.joinToString("") { b -> "%02x".format(b) }
        }
        val registrationClient = RegistrationClient(caFile.inputStream())
        val reg = registrationClient.register(cn, raUrl, vppUrl)

        assertEquals("CN=$cn", reg.subject)
        assertTrue("user certificate must chain to the RA", reg.userCertChainsToRa)
        assertEquals("enrolled", reg.enrollStatus)
        assertTrue("Cert_VPP must chain to the RA", reg.vppCertChainsToRa)

        val pairing = PairingClient(caFile.inputStream(), reg)
        val p = pairing.pair(applianceUrl, vppUrl, mtlsUrl)

        assertEquals("paired", p.status)
        assertEquals("the appliance must record US as its owner", "CN=$cn", p.owner)
        assertTrue("owner proof signature must verify", p.proofSignatureValid)
        assertTrue("VEN certificate must chain to the RA", p.proofCertChainsToRa)
        assertTrue("proof must bind to our identity", p.proofOwnerMatches)
        assertTrue("declared P (${p.parameters["P"]}) must equal the certified one " +
                "in ${p.venSubject}", p.powerMatchesCertified)
        val nominalPower = p.parameters["P"] ?: 0
        assertTrue("P must be a positive number of watts", nominalPower > 0)

        val parts = p.ownerProof.split(".")
        val tampered = parts[0] + "." + parts[1].dropLast(2) + "AA." + parts[2]
        try {
            pairing.forwardOwnerProof(mtlsUrl, tampered)
            fail("the VPP accepted a tampered owner proof")
        } catch (e: IllegalStateException) {
            assertTrue("expected HTTP 400, got: ${e.message}",
                e.message!!.contains("400"))
        }

        val bound = pairing.forwardOwnerProof(mtlsUrl, p.ownerProof)
        assertEquals("bound", bound.status)
        // Java's RFC 2253 form escapes the '=' inside OU=P=2000; Python's RFC 4514 form does not.
        assertEquals(p.venSubject.replace("\\", ""), bound.ven)
        assertEquals("CN=$cn", bound.owner)

        val session = pairing.session(mtlsUrl)
        assertTrue("mTLS session must authenticate us: $session",
            session.contains("\"authenticated\": true") ||
            session.contains("\"authenticated\":true"))
        assertTrue("session user must be us: $session", session.contains("CN=$cn"))

        try {
            pairing.pair(applianceUrl, vppUrl, mtlsUrl)
            fail("the appliance accepted a second pairing while configured")
        } catch (e: IllegalStateException) {
            assertTrue("expected HTTP 409, got: ${e.message}",
                e.message!!.contains("409"))
        }

        // Full week: the appliance executes an activation only inside a declared slot, and the
        // DR event below targets the current UTC window.
        val op = OperationalClient(caFile.inputStream(), reg)
        val allWeek = OperationalClient.DAYS.toSet()
        val slots = OperationalClient.weeklySlots(allWeek, 0, 24)

        val declared = op.declareAvailability(mtlsUrl, bound.ven, slots)
        assertEquals("declared", declared.vppStatus)
        assertEquals(7L * 48, declared.declaredSlots)
        assertTrue("the VPP must echo the calendar version", declared.version > 0)

        val plain = OkHttpClient()
        postJson(plain, "$applianceUrl/poll", emptyMap())
        assertTrue("the appliance must adopt the owner-signed calendar",
            waitUntil {
                getJson(plain, "$applianceUrl/status")["availability_declared"] == true
            })

        val mine = op.myAppliances(mtlsUrl)
        assertEquals("the user owns exactly one appliance", 1, mine.size)
        assertEquals(bound.ven, mine[0].ven)
        assertEquals(nominalPower, mine[0].nominalPower)
        assertEquals("1".repeat(48), mine[0].availability!!.getValue("mon"))

        try {
            op.declareAvailability(mtlsUrl, "CN=intruso", slots)
            fail("the VPP accepted availability for an unknown appliance")
        } catch (e: IllegalStateException) {
            assertTrue("expected HTTP 404, got: ${e.message}",
                e.message!!.contains("404"))
        }

        wipeOperationalTables()

        // The operator requests the current UTC window (2 h).
        val ca = CertificateFactory.getInstance("X.509")
            .generateCertificate(caFile.inputStream()) as X509Certificate
        val nowUtc = ZonedDateTime.now(ZoneOffset.UTC)
        val day = OperationalClient.DAYS[nowUtc.dayOfWeek.value - 1] // MONDAY=1
        val slotStart = minOf(nowUtc.hour * 2 + nowUtc.minute / 30, 44)
        val slotEnd = slotStart + 4

        val operator = operatorCredential(ca)
        val opMtls = RegistrationClient.buildMutualTlsClient(operator, ca)
        val activate = postJson(opMtls, "$mtlsUrl/dr/activate", mapOf(
            "power_w" to 1000, "day" to day,
            "slot_start" to slotStart, "slot_end" to slotEnd, "action" to "reduce",
        ))
        assertEquals("activated", activate["status"])
        assertEquals(1, (activate["activations"] as List<*>).size)

        postJson(plain, "$applianceUrl/poll", emptyMap())
        assertTrue("the appliance must execute the activation",
            waitUntil {
                (getJson(plain, "$applianceUrl/status")["executed_count"] as Number)
                    .toInt() >= 1
            })
        assertTrue("the appliance must have registered itself as a VEN",
            getJson(plain, "$applianceUrl/status")["registration"] != null)

        postJson(plain, "$applianceUrl/evidence", emptyMap())

        assertTrue("the verified participation must reach the user",
            waitUntil { op.participation(mtlsUrl).count == 1L })
        val summary = op.participation(mtlsUrl)
        val part = summary.participations.first()
        assertEquals(day, part.day)
        assertEquals("${slotLabel(slotStart)}-${slotLabel(slotEnd)}", part.interval)
        assertEquals("reduce", part.action)
        assertEquals(50L, part.reductionPct)
        // 2000 W x 50% x 2 h = 2 kWh; at 0.15 EUR/kWh -> 0.30 EUR
        assertEquals(2.0, part.energyKwh, 0.001)
        assertEquals(0.30, part.rewardEur, 0.001)
        assertEquals(summary.totalRewardEur, part.rewardEur, 0.001)
    }

    /** The QR the appliance serves must decode to its own pairing URL, and that URL must answer. */
    @Test
    fun qrEncodesTheAppliancePairingUrl() {
        val plain = OkHttpClient()
        val png = plain.newCall(Request.Builder().url("$applianceUrl/qr").build())
            .execute().use { r ->
                check(r.isSuccessful) { "GET /qr -> HTTP ${r.code}" }
                r.body!!.bytes()
            }
        val decoded = MultiFormatReader().decode(
            BinaryBitmap(HybridBinarizer(decodePng(png))),
            mapOf(DecodeHintType.TRY_HARDER to true)).text

        assertTrue("QR must encode the local pairing URL, got: $decoded",
            decoded.matches(Regex("http://\\d{1,3}(\\.\\d{1,3}){3}:8082")))
        val ping = plain.newCall(Request.Builder().url("$decoded/ping").build())
            .execute().use { it.body!!.string() }
        assertTrue("the URL inside the QR must answer /ping: $ping",
            ping.contains("appliance"))
    }

    /** Grayscale PNG to zxing luminance source without java.awt (android.jar). */
    private fun decodePng(png: ByteArray): RGBLuminanceSource {
        val reader = PngReaderInt(png.inputStream())
        val info = reader.imgInfo
        check(info.channels == 1 && !info.indexed) { "expected grayscale PNG, got $info" }
        val w = info.cols
        val h = info.rows
        val bd = info.bitDepth
        val maxVal = (1 shl bd) - 1
        val perByte = if (bd < 8) 8 / bd else 1
        val pixels = IntArray(w * h)
        for (y in 0 until h) {
            val scan = reader.readRowInt().scanline
            // pngj hands the row packed (8/bd samples per byte) or already expanded.
            val isPacked = scan.size < w
            for (x in 0 until w) {
                val sample = if (isPacked) {
                    val shift = (perByte - 1 - (x % perByte)) * bd
                    (scan[x / perByte] shr shift) and maxVal
                } else scan[x]
                val v = sample * 255 / maxVal
                pixels[y * w + x] = (v shl 16) or (v shl 8) or v
            }
        }
        reader.end()
        return RGBLuminanceSource(w, h, pixels)
    }

    /** Same cleanup the repo's gates do, so activations/evidence do not pile up. */
    private fun wipeOperationalTables() {
        val db = File(repoDir, "vpp-server/vpp.db").absolutePath.replace('\\', '/')
        val code = "import sqlite3; c = sqlite3.connect(r'$db'); " +
                "c.execute('DELETE FROM evidence'); " +
                "c.execute('DELETE FROM activations'); c.commit()"
        val proc = ProcessBuilder(python.absolutePath, "-c", code)
            .redirectErrorStream(true).start()
        check(proc.waitFor() == 0) {
            "could not reset operational tables: " +
                    proc.inputStream.bufferedReader().readText()
        }
    }

    /** Polls until it holds or ~10 s pass: the appliance's own VTN polling may win the race against the manual poll. */
    private fun waitUntil(timeoutMs: Long = 10_000, probe: () -> Boolean): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (probe()) return true
            Thread.sleep(500)
        }
        return false
    }

    private fun slotLabel(slot: Int) = "%02d:%02d".format(slot / 2, (slot % 2) * 30)

    /** RA-issued OU=role=operator credential; fresh name because the CA issues one live certificate per subject. */
    private fun operatorCredential(ca: X509Certificate): RegistrationClient.UserCredential {
        val keyPair = KeyPairGenerator.getInstance("EC")
            .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val tag = ByteArray(3).let { SecureRandom().nextBytes(it); it.joinToString("") { b -> "%02x".format(b) } }
        val subject = X500NameBuilder(BCStyle.INSTANCE)
            .addRDN(BCStyle.CN, "test-operator-$tag")
            .addRDN(BCStyle.OU, "role=operator")
            .build()
        val csr = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
            .build(JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private))
        val issued = postJson(
            RegistrationClient.buildServerAuthClient(ca), "$raUrl/ra/issue",
            mapOf("csr" to RegistrationClient.toPem("CERTIFICATE REQUEST", csr.encoded)),
        )
        val certPem = issued["certificate"] as String
        val cert = CertificateFactory.getInstance("X.509")
            .generateCertificate(certPem.byteInputStream()) as X509Certificate
        return RegistrationClient.UserCredential(keyPair.private, cert, certPem)
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

    private fun getJson(client: OkHttpClient, url: String): Map<String, Any> {
        val req = Request.Builder().url(url).build()
        client.newCall(req).execute().use { r ->
            val text = r.body!!.string()
            check(r.isSuccessful) { "HTTP ${r.code} $url -> ${text.take(200)}" }
            return JSONObjectUtils.parse(text)
        }
    }
}
