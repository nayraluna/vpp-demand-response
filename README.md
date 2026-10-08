# Secure Demand Response Platform for Virtual Power Plants using Residential IoT Devices

Households prove their electricity reductions **cryptographically**, so a grid operator can pay for a curtailment that happened without monitoring what people do at home.

Bachelor's thesis, URV, 2026.

## The problem

Demand response (DR) works today with large industrial consumers: when the grid is strained they cut consumption and get paid. Extending it to homes has two obstacles.

**Proof.** The operator needs to know the reduction happened. Continuous metering would prove it, and would also reveal when you shower, cook or sleep.

**Trust.** The home is not a trusted environment, and the coordinator is not trusted to respect what the user agreed to.

The platform answers both with cryptography instead of surveillance. The user declares *when* each appliance may be curtailed, the appliance enforces that declaration itself, and no reward exists without a signed proof the platform has verified.

## Components

| Component | Role | Stack |
|---|---|---|
| `android-app/` | User app: identity, pairing, availability, rewards | Kotlin, Jetpack Compose, Hilt |
| `vpp-server/` | Coordinator, acts as the OpenADR **VTN** | Python, FastAPI + a mutual-TLS listener |
| `appliance/` | The controllable load, acts as the OpenADR **VEN** | Python on a Raspberry Pi, software HSM |
| `ca/` | Certificate authority and issuance service | Python, FastAPI |
| `backoffice/` | Synthetic fleet and DR-operator CLI | Python |

![Deployment topology. The home network holds the mobile app and the appliance, the platform holds the CA and the VPP. Every connection is opened from the home outwards, so nothing reaches into the house.](docs/deployment-topology.png)

## Security design

One X.509 root, P-256 keys throughout. RSA remains only on the DNIe.

**Identity is certified, not declared.** The appliance's nominal power is in its certificate subject (`OU=P=2000`). An appliance that inflates it at pairing is caught: the value it signs must match the certificate it presents.

**Every channel across the network is mutually authenticated.** The listener reads the client certificate off the TLS socket and maps its subject to an account and a role.

**Every artefact that outlives its channel is signed as JWS.** A channel proves who *delivered* a message, not who *produced* it.

| Artefact | Signed by | Purpose |
|---|---|---|
| Configuration bundle | User | Tells the appliance, authentically, who is enrolling it |
| Owner proof | Appliance HSM | Binds the device to its owner and its certified parameters |
| Availability calendar | User | Weekly schedule, with a monotonic version that blocks rollback |
| Participation evidence | Appliance HSM | The signed record a reward requires |
| Revocation and renewal requests | Operator, certificate holder | Carry their own certificate, because the CA's listener has no client certificates |

The user's key is generated in the Android Keystore and is non-exportable. The app signs the CSR, the pairing bundle, the calendar and the mTLS handshake in place.

**The appliance enforces its owner's calendar locally.** Not even the coordinator can activate it outside the declared slots, its maximum curtailment time or its recovery period. Activations arrive by outbound polling only, so nothing connects *into* the home. The appliance trusts only the root installed at the factory next to its signing key.

**Credentials are revoked and renewed.** An operator revokes by serial with a signed request. The CA publishes an RFC 5280 CRL signed with the root key, with a monotonic CRL number and a 24 hour validity, named in every leaf's distribution point. The VPP checks it on every mutual-TLS request and at enrolment, and relays it to the appliance, which verifies it against its factory root, refuses a lower number and stops acting when its copy expires. The CA issues one live certificate per subject. Renewal re-keys under the same subject and supersedes the old certificate in the same act.

**Identity proof with the Spanish eID.** The app reads the DNIe over NFC through a PACE channel, validates the chain to `AC RAIZ DNIE 2`, and has the chip sign a fresh nonce with the user's PIN, so a copied public certificate cannot pass for a login.

## Verification

```
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

16 gates, 184 checks. Every protocol step runs against its positive *and* its negative cases over the real stack, with real TLS and a real database: certificates outside the chain, invalid signatures, replayed activations, forged capacities, evidence submitted twice, revoked credentials at the mutual-TLS door, a rolled-back revocation list, and a rolled-back calendar planted directly in the row the appliance polls.

`RegistrationFlowTest` drives the app's real protocol clients against the live servers from the JVM. `tests/verify_pi.py` runs a complete DR event against a Raspberry Pi over a real network (11 checks). Registration, QR pairing and DNIe login were completed on a physical phone.

## Limitations

The HSM is emulated, the curtailment is simulated, identity is not verified at issuance, and the PKI departs from enterprise practice in ways a reviewer would flag. Every item, with the standard and the fix, is in [docs/FUTURE_WORK.md](docs/FUTURE_WORK.md).

## Running it

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python provision_all.py                      # root, then each component's own key and CSR
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

Driving it by hand, with the phone, a Raspberry Pi and the synthetic fleet, is [RUNBOOK.md](RUNBOOK.md). [TROUBLESHOOTING.md](TROUBLESHOOTING.md) covers what looks broken but is not.

> **No key material is in this repository.** `provision_all.py` builds the PKI locally, each component generating its own key and obtaining its certificate from a CSR. `*.key`, `*.pem`, `*.p12`, `*.crt` and friends are refused by `.gitignore` as patterns, not paths. Two public exceptions: the DNIe root of the Spanish police, and the development CA root the Android app needs to compile.

## Building the Android app

The app has its own [README](android-app/README.md): architecture, session storage, and how the DNIe login proves possession of the card.

The DNIe login needs the FNMT DNIeDroid SDK, which ships under its own terms and is not redistributed here. Request it from the FNMT and drop `dniedroid-release.aar` into `android-app/app/libs/`. The rest of the system, including the whole verification suite, runs without the Android project.

## About

Built from the reference protocol of a research group at URV, developed together with the Graduate School of Engineering Science at Yokohama National University. My work was to turn that design into a system that runs, and to verify that it does.

## License

MIT, see [LICENSE](LICENSE). It covers this implementation, not the FNMT SDK referenced above.
