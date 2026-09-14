import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

// Reads `vpp.lan.host` from local.properties (gitignored) or from a -P gradle
// property, in that order. Returns "" when unset.
fun lanHost(): String {
    val props = Properties()
    File(rootDir, "local.properties").takeIf { it.exists() }
        ?.inputStream()?.use { props.load(it) }
    return props.getProperty("vpp.lan.host")
        ?: (findProperty("vpp.lan.host") as String?)
        ?: ""
}

android {
    namespace = "com.example.tfgvpp"
    compileSdk {
        version = release(36)
    }

    defaultConfig {
        applicationId = "com.example.tfgvpp"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        // Address an *appliance* uses to reach the VPP. The phone itself talks
        // to the services over the emulator alias or an adb-reverse tunnel, but
        // the address it hands to an appliance during pairing must be reachable
        // from that appliance's own network -- a Raspberry Pi can never reach a
        // 127.0.0.1 it was handed. Set it in local.properties (gitignored, so
        // nobody's home network address ends up in the repository):
        //
        //     vpp.lan.host=192.168.1.50
        //
        // and add the same address to the certificate SAN when generating the
        // PKI:  EXTRA_SAN_IPS="192.168.1.50" bash make_certs.sh
        //
        // Left empty, the app falls back to the host it uses itself, which is
        // correct for emulator-only and USB-tethered runs.
        buildConfigField("String", "VPP_LAN_HOST", "\"${lanHost()}\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
}

// --- dev convenience: restore the adb reverse tunnels on every install -------
// A physical phone reaches the PC's services through `adb reverse` over USB,
// and those tunnels vanish whenever the cable is unplugged or the phone
// reboots. Hooking them to installDebug means pressing Run in Android Studio
// always recreates them. Silently does nothing when no device is attached.
// Standalone use (replugged the phone, app already installed): .\gradlew adbReverseVpp
val adbReverseVpp = tasks.register("adbReverseVpp") {
    doLast {
        val props = Properties()
        File(rootDir, "local.properties").takeIf { it.exists() }
            ?.inputStream()?.use { props.load(it) }
        val sdkDir = props.getProperty("sdk.dir") ?: System.getenv("ANDROID_HOME")
        val adb = sdkDir?.let { File(it, "platform-tools/adb.exe") }
        if (adb == null || !adb.exists()) return@doLast
        val ok = listOf(8080, 8081, 8082, 8443).count { port ->
            runCatching {
                ProcessBuilder(adb.absolutePath, "reverse", "tcp:$port", "tcp:$port")
                    .redirectErrorStream(true).start().waitFor() == 0
            }.getOrDefault(false)
        }
        println(
            if (ok == 4) "adb reverse tunnels ready: 8080, 8081, 8082, 8443"
            else "adb reverse: no device attached (tunnels not set) -- fine for emulator runs"
        )
    }
}
afterEvaluate { tasks.findByName("installDebug")?.finalizedBy(adbReverseVpp) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.kotlinx.coroutines.android)

    // ── UI: Jetpack Compose (Material 3), single-Activity + Navigation ───────
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    debugImplementation(libs.compose.ui.tooling)

    // ── DI: Hilt ─────────────────────────────────────────────────────────────
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)

    // ── Session persistence (certificates; the private key lives in Keystore)
    implementation(libs.androidx.datastore.preferences)

    // ── Protocol clients: OkHttp (custom TrustManager + mTLS KeyManager) and
    //    JWS (RFC 7515) signing/verification ───────────────────────────────────
    implementation(libs.okhttp)
    implementation(libs.nimbus.jose.jwt)

    // Pairing: scan the appliance's QR (encodes its local pairing URL)
    implementation(libs.zxing.android.embedded)

    // ── DNIe login (FNMT DNIeDroid SDK v2.3.111) ─────────────────────────────
    // The .aar is the signed library shipped by CNP-FNMT (verified with
    // `jarsigner -verify` -> "jar verified"). The rest mirror the versions the
    // SDK's own Sample_DNIe_App declares; BouncyCastle must stay on the old
    // `jdk15on` artifacts because that is what the SDK was built against.
    implementation(files("libs/dniedroid-release.aar"))
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)
    implementation(libs.bouncycastle.bctls)
    implementation(libs.jsoup)
    implementation(libs.okhttp.urlconnection)
    // NOTE: the SDK sample also lists `com.gemalto.jp2:jp2-android:1.0.3`, but it
    // only lived on jcenter (shut down in 2021) and is unresolvable today. It is
    // used exclusively to decode the DNI *photo* (MRTD DG2), which this login does
    // not read, so it is omitted. Re-add it if you ever display the photo.
    // PasswordUI (the SDK's PIN dialog) uses Material components; DnieLoginActivity
    // keeps a classic View layout because the SDK drives its own dialogs.
    implementation(libs.androidx.appcompat)
    implementation(libs.google.material)

    // ── Unit tests ───────────────────────────────────────────────────────────
    testImplementation(libs.junit)
    // JVM flow test: runs the real protocol clients against the live local
    // servers (see src/test/.../RegistrationFlowTest.kt). zxing core plus a
    // pure-Java PNG reader: unit tests compile against android.jar, which has
    // no java.awt/ImageIO.
    testImplementation(libs.zxing.core)
    testImplementation(libs.pngj)
}
