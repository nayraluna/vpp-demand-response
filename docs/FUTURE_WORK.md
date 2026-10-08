# Limitations and future work

What the prototype does not do, what a PKI engineer reading it would flag, and
what has been fixed since the thesis was delivered. Each item says what the
code does today, what the standard or the production version looks like, and
the fix. Grouped by area, the PKI first.

## PKI

### RA and CA are one process, and the root key is online
`ca/app/ra_service.py` loads `certs/CA.key` and signs leaves directly. The
Registration Authority (request validation, identity vetting) and the
Certification Authority (holder of the signing key) are one process on an
internet facing host, and the root key is a PEM file beside the leaves.

Production: offline root, online issuing sub CA with its key in an HSM, and the
RA as a separate front office with no access to any CA key. A compromise of the
RA host must not allow minting certificates. Large.

### Issuance verifies possession, not identity
`/ra/issue` accepts any well formed CSR whose self signature verifies, whose
public key has not been seen before and whose subject holds no live
certificate. Anyone who reaches port 8081 obtains a certificate with the
subject they choose, including `OU=P=<watts>` for an appliance or
`OU=role=operator` for the backoffice.

Production: the RA checks that the requester is entitled to the requested
subject. Appliances are provisioned at the factory over an internal channel,
operators through an authenticated onboarding, users through the DNIe proof
below. Medium.

### The DNIe check is client side and not bound to the enrolment
`DnieAuth.kt` validates the card chain to `AC RAIZ DNIE 2` and verifies a
signature over a fresh nonce, but the RA never sees any of it. A modified app
or a plain HTTP client can skip the DNIe step entirely. The DNIe currently adds
user experience, not platform security.

Fix: the RA issues a challenge nonce. The app has the card sign
`nonce || SHA-256(CSR)` and sends CSR, DNIe authentication certificate with
chain, and that signature. The RA validates the chain to the DNIe root, checks
expiry and OCSP against the police responder, verifies the signature, and only
then approves the request for the CA to sign. The RA keeps the mapping from DNI
to platform pseudonym in its own database and can enforce one credential per
person. The DNIe certificate never enters the platform certificate, so the
pseudonym is preserved. This mirrors how EST or CMP enrol with an existing
credential. Medium.

### The operator role is self declared
`backoffice/dr_operator.py init` builds a CSR with `OU=role=operator` and the
CA signs it with no check. The VPP then authorises `/dr/select` and
`/dr/activate` purely on that OU (`_is_operator`). The operator credential is
the most privileged one in the platform and today anyone who can reach port
8081 can obtain it.

Fix: the RA must never take a role from the CSR. Operator issuance goes through
an authenticated onboarding, and the RA sets the role itself from that
decision. In production the operator credential would also be short lived and
stored in an HSM or smart card. Medium.

### The user subject is the DNI, and the key is not attested
After a DNIe login the certificate's CN is the DNI itself, so the national
identifier travels in the x5c header of every calendar and in the pairing
bundle over plain HTTP. Without a DNIe the app picks `CN=android-<random>`,
which nothing ties to a person. The Keystore key is generated without an
attestation challenge, so the RA cannot tell a hardware key from a software
one.

Fix: with the DNIe binding above, the RA assigns the pseudonym, and the app
sends the Android key attestation chain with the CSR. Medium.

### Attributes and roles live in the subject DN
`OU=P=2000` and `OU=role=operator` are copied from the CSR and parsed by prefix
in five places (`mtls_server._is_operator`, `owner_proof`, `hsm.nominal_power`,
`ra_service`, `PairingClient.kt`).

Standard: entity attributes go in a private extension under an own OID arc
(RFC 5280 private extensions) or an attribute certificate (RFC 5755). Roles are
an EKU or a certificatePolicies OID the CA sets. Device identity follows
IEEE 802.1AR. Fix: the CA writes the extension from the profile, exactly as it
already does for KU and EKU, and the readers read the extension. Medium.

### DN strings are the identity and the database key
`rfc4514_string()` keys users, appliances and VENs and is the mTLS identity.
RFC 4514 and Java's RFC 2253 output differ in escaping and ordering, so a name
that two libraries render differently is two accounts.

Standard: compare `Name` objects, as renewal already does, identify a
certificate by issuer plus serial, and key accounts on an identifier the CA
assigns. Keying on the subject rather than the serial is deliberate, it
survives re-key. The fragility is only the string form. Medium.

### Enrolment, renewal and revocation are bespoke JSON endpoints
PKCS#10 in and X.509 out are standard, the envelope is not: `/ra/issue` takes
`{"csr": PEM}`, renewal is a JWS carrying a CSR, revocation a JWS naming a
serial.

Standard: EST (RFC 7030) with `/cacerts`, `/simpleenroll` and
`/simplereenroll`, `application/pkcs10` in and `application/pkcs7-mime` out,
re-enrolment authenticated by TLS client auth, which is what the JWS with x5c
does by hand. CMP (RFC 4210) for the heavy version. An EST facade over
`issue_from_csr` is thin. Medium.

### Signed requests have no freshness, audience or type binding
No `iat`, `exp`, `jti` or `aud` in any payload, and the `typ` header is set by
every producer and checked by no verifier. Replays are harmless by idempotence
(revoke twice is 409, the calendar has a version, evidence is unique per
activation), not by design. The pairing bundle names no appliance and never
expires, so it can be replayed to any factory-reset appliance while the owner
certificate lives.

Standard: RFC 8725 explicit typing, RFC 7519 claims, CMP nonces. Small.

### Renewal revokes the old certificate at once
No overlap window, so the appliance refuses its owner until the calendar is
signed again with the new key.

Standard: both certificates valid for a grace period, the old one withdrawn
once the new one is confirmed in use. Fix: a grace window in
`live_serial_for_subject` and in the VPP enrol check. Medium.

### Revocation is a CRL, not OCSP, and the app never consumes it
Relying parties decide from a list they already hold, which is what an
appliance without network access needs, and nothing answers live status
queries. The Android app verifies the appliance and VPP certificates against
the root but never fetches the CRL. Small for the app, medium for OCSP.

### The app validates the platform chain with a raw signature check
`cert.verify(root); checkValidity()` in `RegistrationClient`, `SessionManager`
and `PairingClient`, while the DNIe gets `CertPathValidator`. No issuer profile
check, no revocation. Fix: the same PKIX call for both. Small.

### DNIe validation gaps
`isRevocationEnabled = false`, no DNIe policy OIDs as initial policies, the DNI
taken from the RFC 2253 string by regex instead of the `serialNumber` RDN. The
lenient PKCS#1 verifier runs only after strict JCA verification fails, keeps
padding, separator and hash strict, and tolerates only the DigestInfo OID
prefix that renewed cards emit. Medium for OCSP, small for the rest.

### The owner proof signature is not kept
`_owner_proof` verifies the appliance signed proof and stores only the parsed
relation (VEN, owner, P, max, rec). The evidence, by contrast, is stored as the
verbatim JWS. If the ownership relation in the database is questioned, there
is nothing signed by the appliance to show. Fix: store the proof JWS with the
appliance row. Small.

### Evidence is verified once and has no long-term validation data
The JWS that drives a payment is verified at submission and kept verbatim. No
later path compares a participation row against it, and the reward is
computed from the row's own columns, so a `reduction_pct` edited in the
database changes a payout without invalidating anything. There is no RFC 3161
timestamp and no record of the CRL number and anchor at verification time, and
an expired certificate leaves the CRL, so the signature cannot be re-verified
once its certificate expires. The availability path is the opposite: the
appliance re-verifies the calendar on every poll.

Standard: CAdES or JAdES with a timestamp and archived validation data.
Medium to store the verification context, large for a timestamping authority.

### Activations are unsigned
They rest on the mutual-TLS channel, against the rule that what outlives a
channel is signed. `crypto_service.sign_jws` (typ `dr-event`) exists and
nothing calls it. Fix: sign the activation and let the appliance keep the order
beside its evidence. Small to medium.

### Trust anchor rollover is a rebuild
`/ra/certificate` cannot bootstrap anyone, it is served over TLS that only the
same root verifies. Anchors are copied out of band into the APK, the Pi and the
operator, and regenerating the root invalidates everything.

Standard: a new root cross-signed by the old one and a window where verifiers
hold both. The appliance holds one `CA.crt`. Large.

### VPP certificate is dual use
`vpp.crt` carries serverAuth and digitalSignature at once, one certificate per
entity as in the paper, and the signing half is unused in production. A
stricter deployment separates the TLS identity from the document signing
identity so the two keys can be rotated and protected independently.

### TLS SANs are development addresses
The server certificates list `localhost`, `127.0.0.1`, the Android emulator
address `10.0.2.2` and any IP passed in `EXTRA_SAN_IPS`, and the CRL
distribution point is `TFG_CRL_URL`. Production certificates would carry the
real DNS names of the services and nothing else.

### HSM is emulated
The appliance signing key is a file on disk (`VEN.key`, or the Pi filesystem).
The design assumes a hardware element that generates the key and signs
internally. The prototype never exercises the HSM interface (PKCS#11 or a
vendor API), so integration with a real secure element is untested.

### Minor profile details
No certificatePolicies, no AIA, no CP or CPS document. One validity for every
profile. `hsm.sign` and `crypto_service.sign` return a bare hex signature with
no algorithm identifier and are used only by `verify_setup`.

## Appliance and protocol

### The curtailment is simulated and selection ignores the reduction fraction
The appliance never measures anything: `activation_service` hard codes 100
percent for a `shutdown` action and 50 for a `reduce` action, and the evidence
certifies that the appliance received and acknowledged the order, not how much
power it shed. Selection accumulates the full `nominal_power` of every chosen
appliance regardless of the action, so a `reduce` activation is promised at
100 percent and delivered at 50. A 4000 W request served by two 2000 W
appliances under `reduce` sheds 2000 W.

Fix: make the action carry the requested reduction and have selection
accumulate `nominal_power` times that fraction. On the appliance, read the
reduction actually applied from the device controller or a power meter behind
the same signing boundary, and sign that value. Where no measurement exists,
the evidence should state that the figure is the commanded reduction.

### Selection is a greedy heuristic
Fewest appliances first, largest contributions until the request is covered.
Not an optimisation, and fairness across households is not considered.

### No event reconciliation
Selection assumes every chosen appliance delivers its full share. After
`/dr/activate` the VPP only waits for evidence. A refusal at the appliance stays
in its local log, an appliance that never polls produces no evidence and no
error, nothing compares the evidence received against the activations issued,
and there is no reserve.

Fix: an event identifier that groups the activations of one call and a
reconciliation step at `ends_at` plus a grace period, refusals reported to the
VTN in the next poll (OpenADR does this with `oadrCreatedEvent` carrying
`optOut`), a configurable reserve in selection, and remuneration settled
against the reconciled event.

### Pull latency and the refusal of future activations compound
The appliance uses the OpenADR pull model so that it never listens on the
internet. The cost is latency: an activation is only seen at the next poll, so
the operator must issue it at least one poll interval before its window starts.
Today `activation_service._check` refuses an activation whose window has not
started, the VTN marks it delivered on the first poll, and the appliance
appends it to `processed` even when refused. An activation issued in advance is
delivered once, refused, and lost.

Fix, appliance side: a window already elapsed is refused, a window in progress
executes now, a window in the future is queued and executed when the clock
enters it, re-checking the calendar, `max` and `rec` at that moment. Fix, VTN
side: keep delivering an activation until the appliance acknowledges it or its
`ends_at` has passed. For sub-minute grid signals the option that keeps the
same advantages is a persistent outbound connection (WebSocket or MQTT) over
the same mTLS identity.

### The local pairing interface is always exposed
One FastAPI process serves `/qr`, `/pair`, `/config`, `/factory-reset`,
`/poll`, `/evidence` and `/status` on the same port for the whole life of the
appliance. `/factory-reset` is reachable by anyone on the LAN with no
authentication.

Fix: bind the pairing endpoints only while the state is 0 and shut them down
after a successful pair. Factory reset should require a physical action on the
device or the owner's signature. The poll and status endpoints exist for the
test suite and should not be part of the production surface.

### The bundle carries an unused bootstrap URL
The bundle has both `vpp_url` and `vpp_mtls_url`, and the appliance reads only
the second. Since the appliance holds a factory certificate it never needs an
unauthenticated endpoint. Keep one URL.

### OpenADR naming is only partially aligned
The VEN registration exchange uses the OpenADR 2.0b names (`venName`,
`oadrProfileName`, `venID`, `registrationID`, `oadrRequestedOadrPollFreq`).
The poll returns `activations` where OpenADR would return `oadrDistributeEvent`
with `eiEvent` entries, an activation carries `activation_id`, `day`,
`slot_start`, `slot_end` and `action` where the OpenADR event carries
`eventID`, `modificationNumber`, `dtstart`, `duration` and `eiEventSignal`, the
evidence has no OpenADR name (closest is `oadrUpdateReport`), and the signed
calendar has no counterpart. Renaming the fields and wrapping the poll as
`oadrDistributeEvent` would let a standard VEN library parse the events with a
thin adapter.

### Appliance replay state grows without bound
`cfg["processed"]` is an append only list. Since every activation carries
`ends_at`, entries older than that can be pruned.

### Scale is untested
One physical appliance, with fleet behaviour exercised through a synthetic
population of 20 users and 40 appliances.

## Resolved since the thesis

- Revocation and renewal: CA register, `/ra/revoke`, `/ra/crl`, `/ra/renew`,
  checked at the mTLS door, at enrolment and on the appliance, renewal as
  re-key with the old serial superseded (89cc27d).
- The activation nonce, redundant with a 128 bit activation identifier
  (b51c25b).
- Trust on first use at pairing: the appliance ships with the factory root and
  ignores any root the bundle carries (226cfb0).
- Central key generation and PKCS#12 shipping: each component generates its
  own key and enrols through a CSR, platform identities signed offline with a
  profile the requester does not choose (73206b6).
- Validity period checked wherever a certificate is trusted, not only at the
  TLS handshake (b5549c2).
- One live certificate per subject at the CA, and no account takeover at
  enrolment while the old certificate stands (201e69e).
- The VPP refuses its cached revocation list past `nextUpdate` (4895d66).
- The DNIe diagnostic no longer drives the qualified signature key (01ec481).
- Verifiers are algorithm agnostic and the platform runs on P-256 (585f05c,
  07a160c).
- The revocation list is an RFC 5280 CRL with CRLNumber, AKI, reason codes and
  a distribution point in every leaf (f8cc108).
- Root KeyUsage limited to keyCertSign and cRLSign, `notBefore` backdated,
  CSRs with an empty subject or the CA's name refused, the register keeps the
  certificate, its profile and who revoked it, serials accepted as any tool
  prints them, issuer checks require a valid CA and an end entity leaf
  (a000510).
