# Runbook

How to bring the whole platform up, exercise it end to end, and collect the
measurements. Every step gives the command and what it produces.

Anything that looks like a failure but is not is in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md).

**Preconditions:** 
- `.venv` installed (`pip install -r requirements.txt`)
- `certs/` generated: `cd certs && bash make_certs.sh` in Git Bash. Replacing an
  existing CA is a different job, see [the appendix](#appendix-regenerating-the-ca)
- Raspberry Pi off
- Activate the venv in every new terminal: `.venv\Scripts\activate`.

---

## 1. Verification suite

```powershell
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

Ends in `ALL GATES PASSED`.

The script frees ports 8080, 8081, 8082 and 8443 before starting, so the gates
always run against their own services with their own environment. A failing
gate is therefore a real failure. Investigate it rather than re-running.

---

## 2. Services for manual testing

Steps 3 to 5 need the services up.

```powershell
$env:TFG_POLL_SECONDS = "60"
powershell -ExecutionPolicy Bypass -File .\start_services.ps1
```

- `TFG_POLL_SECONDS = 60` gives the appliance its production polling loop
- `start_services.ps1` listens on `0.0.0.0`, which the phone needs. For local only runs, set `$env:TFG_MTLS_HOST = "127.0.0.1"` **before** starting.

Check the services answer:

```powershell
curl.exe -k https://127.0.0.1:8080/ping   # "service":"vpp"
curl.exe -k https://127.0.0.1:8081/ping   # "service":"ca"
curl.exe http://127.0.0.1:8082/ping       # "service":"appliance","state":1
```

Each endpoint is expected to return `"status":"ok"` and the corresponding service name.

---

## 3. JVM flow test

Drives the app's real protocol clients against the live local servers.

```powershell
cd android-app
.\gradlew.bat testDebugUnitTest
cd ..
```

Report at `android-app/app/build/reports/tests/testDebugUnitTest/index.html`.

Without the services from [step 2](#2-services-for-manual-testing) running, the tests skip themselves through `assumeTrue` and the build still succeeds. Check that they actually ran.

---

## 4. Scenario

### 4a. Registration, pairing and availability from the phone

| # | Do this | Expected |
|---|---|---|
| 1 | Install the APK from Android Studio (Run) | The `adbReverseVpp` task creates the USB tunnels by itself |
| 2 | **Sign in with DNIe** (card, 6 digit CAN, PIN), or *Use a test identity* on the emulator, then **Create account** | Home Screen, no appliances yet |
| 3 | **Pair appliance**, scanning the QR at `http://127.0.0.1:8082/qr` or pressing *Use development appliance* | owner proof checks, appliance on Home Screen |
| 4 | **Edit availability**, marking at least the current UTC hours, then Save | Availability saved |

Over Wi-Fi instead of USB, put the PC and the phone on the same network and
point the URLs at the PC's LAN address, which has to be in the certificate SAN.

### 4b. E2E event on the real Appliance

> NOTE: Run this before loading the synthetic population (Step 4c)

Selection picks appliances by descending power, so a synthetic 2350 W unit
outbids the real 2000 W one and nothing executes. Run `python backoffice/population.py clear` first if a population is loaded.

For the appliance to **execute** an activation and not merely receive it, `_check()` in `activation_service` demands both:

- `--day` is today in UTC
- the current UTC time falls inside the window

Otherwise it rejects with `activation is for X, today is Y` or
`activation window has not started yet / has already elapsed`. The block below computes both from the clock, so do not type them by hand.

```powershell
python backoffice/dr_operator.py init   # first time only, creates the operator credential

$utc  = [DateTime]::UtcNow
$day  = $utc.DayOfWeek.ToString().Substring(0, 3).ToLower()
$from = $utc.Hour
$to   = $from + 2        # 2 h window, valid while $from is 22 or less
python backoffice/dr_operator.py activate --power 1000 --day $day --from $from --to $to
```

**Check the UTC minutes before running it.** The window ends on the hour, so at minute 58 or later the poll (60 s at most) does not make it. Wait for the next hour and run the block again. Between 23:58 and 00:00 UTC the day also rolls over, and an activation issued before it is rejected.

Prints `ACTIVATED: 1 appliance(s), 2000 W aggregated for 1000 W requested`
with the window and an `act-...` id.

`--from` and `--to` accept `HH` or `HH:MM`. The range runs from 0 to 24 in UTC clock hours, and `--to 24` is valid (slot 48, midnight). Two hours is exactly the appliance's `max_curtail`, so `$from` has to be 22 or less, otherwise the window crosses midnight and the call fails with `invalid slot range`.

Wait 60s for the appliance loop, or force the cycle:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8082/poll
Invoke-RestMethod -Method Post http://127.0.0.1:8082/evidence
```

The app's Participations screen then shows **2.0 kWh and 0.30 EUR**, which is a two hour window at 2000 W reduced by half, priced at 0.15 EUR/kWh.

**More bars.** Run the same block again with different values. Height comes
from the window length and from `--action shutdown`, which reduces by 100 per
cent instead of 50: one 30 minute slot is 0.5 kWh, an hour with reduce is
1.0 kWh, ninety minutes with shutdown is 3.0 kWh, two hours with shutdown is
4.0 kWh, the maximum `max_curtail` allows. Power cannot be raised, it is
certified in the appliance's certificate, which is what `verify_owner_proof`
proves.

Timing is the real constraint. Recovery runs 30 minutes from the end of the
window, so allow roughly an hour of wall clock between bars, and do not start a
window that ends within a minute of the next poll. Synthetic appliances never
appear in the chart, only your own.

The chart's axis uses `executed_at`, the real execution time, not the day of
the DR window, so everything generated in one session carries today's date. It draws the 8 most recent bars at most, then adds "N most recent of M" under the title. On backdating them, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#editing-a-stored-participation-is-not-detected).

### 4c. Synthetic population and aggregated view

```powershell
python backoffice/population.py generate --users 20 --seed 42
python backoffice/population.py aggregate --day tue
```

`--day` is literal here, it picks the weekly profile to display and need not
be today. For the current UTC day:

```powershell
python backoffice/population.py aggregate --day ([DateTime]::UtcNow.DayOfWeek.ToString().Substring(0,3).ToLower())
```

Deterministic: seed 42 always prints `generated 20 users with 40 appliances
(seed 42)` and the same ASCII bar table. On a Tuesday the peak is **21.4 kW
across 15 appliances**, 18:00 to 22:30 UTC. The profile changes with the
weekday.

### 4d. Multi household event at the peak, and an infeasible one

```powershell
python backoffice/dr_operator.py activate --power 6000 --day tue --from 18 --to 19
```

With seed 42 on a Tuesday: `ACTIVATED: 3 appliance(s), 6700 W aggregated for
6000 W requested`, two air conditioners of 2300 W and one of 2100 W. The real
appliance is rejected with `still recovering` only if the 4b event ran within
the last two hours or so.

Literal here too. This shows selection inside the synthetic peak band, which
the VPP resolves whatever the current time is. Synthetic devices are not real,
so nothing executes and Participations does not change.

Infeasible case, a dead band of the profiles:

```powershell
python backoffice/dr_operator.py select --power 6000 --day tue --from 16:30 --to 17:30
```

Prints `NOT POSSIBLE: not possible: available flexibility (0 W) is below the
requested 6000 W` and the list of reasoned rejections.

### 4e. Cleanup, mandatory

```powershell
python backoffice/population.py clear
```

### Scripted alternative

`tests/collect_evaluation_data.py` runs 4b to 4e and measures every latency
(pairing, owner proof, polls, evidence), then cleans up. It needs the
[step 2](#2-services-for-manual-testing) services started with `TFG_MTLS_HOST=127.0.0.1` and `TFG_POLL_SECONDS=3600`.

```powershell
python tests/collect_evaluation_data.py
```

It factory resets the appliance, pairs it as `eval-user-01`, and wipes
`evidence` and `activations` at both ends, so your phone stops seeing
`ven-0001`. Run it before 4a, or re-pair from the phone afterwards.

It ends with `===SUMMARY===` and a JSON block. `method` states how the numbers
were taken and `timings_ms` holds them. Repeatable operations report `p50`,
`p95` and `n` over 15 samples with 2 warm-up runs discarded. Three of them
cannot be repeated without measuring something else, so they carry `n: 1` and a
`single_sample` note saying why: the first poll registers the VEN and adopts the
calendar, an activation is delivered once, and replayed evidence is refused with
409 by design.

Everything is measured over loopback, so these exclude network latency and are
a lower bound. Reference p50 and p95: issuance 20 and 23 ms, enrolment 24 and
31 ms, pairing 71 and 113 ms, owner proof 31 and 45 ms, availability 92 and
123 ms, participation read 19 and 24 ms, empty poll 29 and 36 ms.

---

## 5. Stop the local services

The services run with a hidden window, so stop them by port:

```powershell
foreach ($p in 8080, 8081, 8082, 8443) {
    Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object { Stop-Process -Id $_.OwningProcess -Force }
}
```

Running `start_services.ps1` again also works, it is idempotent.

---

## 6. Physical validation on the Raspberry Pi

Two addresses are site specific: the Pi's address, and this PC's LAN address.
Neither is committed. The PC's address has to be in the certificate SAN, and
the app has to hand that same address to the appliance during pairing, because
a Raspberry Pi can never reach a `127.0.0.1` it was given:

```bash
EXTRA_SAN_IPS="<pc-lan-address>" bash make_certs.sh
echo "vpp.lan.host=<pc-lan-address>" >> android-app/local.properties
```

Regenerating the certificates cascades, so read
[the appendix](#appendix-regenerating-the-ca) before re-running `make_certs.sh`
on an existing setup.

1. **Power the Pi on**, and only now. Check from the PC's PowerShell, not over
   ssh, because the Pi has neither `Invoke-RestMethod` nor `powershell`:

   ```powershell
   Invoke-RestMethod http://<pi-address>:8082/status
   ```

   If it does not answer, ssh in and check the service. Use the hostname, the
   bare IP fails the host key check:

   ```bash
   ssh <user>@<pi-hostname>
   systemctl status appliance
   ```
2. Start the PC services on `0.0.0.0`
   ([step 2](#2-services-for-manual-testing), without pinning loopback).
3. **Factory reset the PC's local appliance**, otherwise it competes with the Pi as the same `ven-0001`:

   ```powershell
   Invoke-RestMethod -Method Post http://127.0.0.1:8082/factory-reset
   ```
4. ```powershell
   python tests/verify_pi.py http://<pi-address>:8082 <pc-lan-address>
   ```

Prints `11 checks passed`: pairing over a real network, self registration, an
activation retrieved by the Pi's outbound poll, single delivery, evidence
signed on the device, and 2.0 kWh to 0.30 EUR.

`verify_pi` wipes `evidence` and `activations` and re-pairs `ven-0001` with a fresh test user, so the phone stops seeing the appliance.

---

## Appendix: regenerating the CA

Only if unavoidable. `CA.crt` is copied into places that do not update
themselves: the APK, the Pi, the operator credential and the VPP database.
Regenerating it invalidates every existing certificate. Full order:

1. Stop the local services and close the app.
2. `cd certs && bash make_certs.sh` in Git Bash. This rebuilds the CA, `vpp.*`,
   `server.*` and `VEN.*`.
3. Clear the old state: delete `vpp-server/vpp.db`, and reset the PC appliance
   by deleting `appliance/config.json`, `appliance/trust_ra.pem` and
   `appliance/trust_vpp.pem`.
4. App: copy `certs/CA.crt` over `android-app/app/src/main/res/raw/ca.crt`,
   rebuild, reinstall the APK, log out in the app and register again.
5. Operator: `python backoffice/dr_operator.py init --force`.
6. Pi: copy `certs/VEN.p12`, `certs/VEN.crt` and `certs/VEN.key` to the Pi's
   `~/certs/`, restart `appliance.service`, factory reset the Pi with
   `POST http://<pi-address>:8082/factory-reset`, and re-pair it.
7. Verify in order: `run_all.ps1`, then the JVM flow test, then `verify_pi.py`.

`ac_raiz_dnie2` is not touched. The DNIe PKI is independent.
