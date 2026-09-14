# Android client

Kotlin app (Jetpack Compose, Material 3) that drives the user's side of the
platform: passwordless registration with the DNIe, appliance enrollment by QR,
weekly availability declaration and the verified participation history.

The private key is generated inside the
Android Keystore and cannot be exported, and the DNIe login is a real proof of
possession over NFC against a physical card.

## Architecture

MVVM + Clean Architecture (simplified: `data` / `domain` / `presentation`),
single Activity with Navigation Compose, Hilt for dependency injection,
coroutines + `Flow` everywhere (no blocking calls outside `Dispatchers.IO`),
DataStore (Preferences) for session persistence.

Two things depart from that shape. `DnieLoginActivity` is the one extra
Activity, because the FNMT SDK takes over NFC reader mode and puts up its own
PIN dialog, so it runs apart and returns the proven identity as an
`ActivityResult`. And the protocol clients under `data/remote/vpp/` import
nothing from Android, which is what lets the JVM flow test drive the real
clients against live servers. `domain/` follows the same rule.

### Repository seam

`di/RepositoryModule.kt` binds each domain repository interface to its
implementation. The interfaces in `domain/repository` are the only thing the
presentation layer sees, so neither the screens nor the use cases change when
an implementation does.

### Session persistence

Registration (and the DNIe identity proof) happens **once** per install:

- private key: generated **inside** the Android Keystore, non-exportable, so
  it signs the CSR, the pairing bundle, the calendar and the mTLS handshake
  in place (custom `X509ExtendedKeyManager` in `RegistrationClient`).
- certificates + identity attributes: DataStore (public material only), with a
  migration from the previous SharedPreferences file.

The splash screen restores the session and skips login when both halves exist.
Logout deletes both (and needs a new registration afterwards).

## Tests

`RegistrationFlowTest` is an end-to-end JVM test of the **real** clients
against the live local servers, skipped automatically when they are not
running.

```
.\gradlew testDebugUnitTest      # flow test (auto-skips without live servers)
.\gradlew assembleDebug          # build
```

## Running it

Open the project in Android Studio with the platform already running from the
repo root. The emulator needs nothing, because it reaches the services at
`10.0.2.2` and that address is in the VPP certificate's SAN. A physical phone
goes over USB, where `installDebug` triggers the `adbReverseVpp` task and the
app then talks to `127.0.0.1` through `adb reverse` tunnels. Only pairing a
real appliance needs more, because the app hands it a URL the appliance has to
reach on its own network: that is the `vpp.lan.host` setting covered in the
root README.

## DNIe login

`DnieLoginActivity` + `data/security/DnieAuth.kt`, built on the **FNMT
DNIeDroid SDK v2.3.111** (`app/libs/dniedroid-release.aar`, signature checked
with `jarsigner -verify` → `jar verified`).

**Requires a physical phone with NFC and a real DNIe 3.0/4.0.** You need the
6-digit **CAN** printed on the card (opens the PACE channel) and the **PIN**
(the SDK shows its own dialog). Three wrong PINs block the card.

What the screen proves, in order:

1. the certificate chain read from the card validates (PKIX) up to
   **`AC RAIZ DNIE 2`**, bundled as `res/raw/ac_raiz_dnie2.crt`,
2. the certificate is inside its validity window,
3. **proof of possession**, the card signs a fresh 32-byte nonce and the
   signature verifies against the certificate's public key,
4. a tampered nonce is rejected (negative control).

Step 3 is what makes this an authentication: certificates are public, so only
a signature over fresh data proves the holder has the card. It picks the
**authentication** certificate (KeyUsage `digitalSignature`), not the
qualified-signature one. Revocation checking (OCSP at `http://ocsp.dnie.es`)
is **not** implemented, a documented gap.

## Notes

- **Trust anchor:** `res/raw/ca.crt` is a **copy** of `certs/CA.crt`. If
  `make_certs.sh` ever regenerates the CA, copy it again.
- The app trusts **only** the platform CA (custom `TrustManager`), never the
  public CA store.
- `Theme.TfgVpp` stays on MaterialComponents (not pure Compose) because the
  FNMT SDK's PIN dialog inflates Material widgets.
- **No Retrofit, on purpose.** Retrofit and kotlinx-serialization are not
  wired in, because the protocol needs per-connection mutual TLS with a
  Keystore-backed KeyManager and dynamic base URLs, which the existing OkHttp
  and Nimbus clients already do and the JVM flow test verifies.
- The calendar keeps the protocol's 48 half-hour slots per day on the wire. The
  UI edits at 1-hour granularity, so each hour maps to two slots.
- **Two gaps are marked in the code** with `TODO(TFG)` comments: revocation
  checking for the DNIe (`data/security/DnieAuth.kt`) and a pseudonymous CN in
  place of the raw DNI (`data/repository/UserRepositoryImpl.kt`).
