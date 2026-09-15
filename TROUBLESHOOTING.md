# Troubleshooting

Things that behave correctly but look like failures, and the traps that cost
the most time. Read this before concluding anything is broken.

## The Raspberry Pi steals activations

A powered Pi stays paired as `ven-0001` and polls every 60 seconds. It shares
that identity with the appliance running on the PC, so whichever polls first
consumes the activation and the other reports `polled: 0`.

`run_all.ps1` isolates itself by pinning mutual TLS to loopback, so the gates
are safe. Manual testing with services on `0.0.0.0` is not. **Keep the Pi off
for everything except the physical validation step.**

## Slots are UTC, your clock is not

Spain in summer is UTC+2. At 19:00 local the current slot is the one starting
at **17:00**. Any activation you expect to see execute has to cover the
current UTC hour, not the current local hour.

## Use 127.0.0.1, never localhost

On Windows, `localhost` pays an IPv6 fallback of roughly two seconds per
request, which ruins any measurement. The suite used to take about five
minutes and now takes about one, with the same checks. The gates and
`verify_pi.py` already follow this rule.

## `still recovering (N min left)` is not a failure

The appliance enforces a 30 minute recovery counted from the end of its last
activation. After a two hour event it stays blocked for about two and a half
hours, and every selection rejects it. Check the clock before assuming
anything broke.

## Orphaned synthetic appliances break the suite

Run `python backoffice/population.py clear` after any demo that generated a
synthetic population. Leftover synthetic appliances outbid the real one during
selection, so the activation goes to a `syn-*` device and nothing executes.

## Port 8082 is plain HTTP

The local pairing channel is HTTP by design, protected by signed artefacts
rather than by the transport. Calling `https://127.0.0.1:8082` returns a
schannel error `SEC_E_INVALID_TOKEN`. That is the client refusing to speak TLS
to a plaintext port, not a broken service.

## Port 8443 missing from the startup table

`mtls_server.py` binds slightly later than the snapshot `start_services.ps1`
prints, so 8443 can be absent from that table while the service is fine.
Confirm with:

```powershell
Get-NetTCPConnection -State Listen | ? { $_.LocalPort -eq 8443 }
```

## `TFG_MTLS_HOST` is read once, at process start

Setting it while services are already running does nothing. Worse, it lingers
in the shell: set it for an isolated local run, forget it, restart for a phone
demo, and mutual TLS stays on loopback where the phone cannot reach it. Clear
it with `Remove-Item Env:\TFG_MTLS_HOST`.

## The first `/ping` after startup can hang

Cold start. `/status` answers immediately.

## Editing a stored participation is not detected

Every row in `evidence` keeps the JWS the appliance signed, and
`verify_evidence` gate G2 does read it back out of SQLite and re-verify the
signature. What it checks is that the payload's `activation_id` matches the
row. Nothing compares the row's own `executed_at` and `reduction_pct` against
the values inside that signed payload.

The payout is computed from the columns, not from the payload.
`evidence_for_owner` in `vpp-server/app/db.py` does not select `jws` at all,
and `remuneration.settle` derives the energy and the reward from
`reduction_pct`, `nominal_power` and the slot bounds. So editing
`reduction_pct` in SQLite changes what the app pays out while the proof sitting
in the same row still verifies and still passes the gate.

The availability path is built the other way round. The appliance re-verifies
the stored calendar JWS on every poll and enforces the monotonic version, which
is why `verify_availability` can plant a rolled back row and a forged issuer
directly in the table and watch the device refuse both.

So do not edit these rows by hand. Nothing would tell you, and the numbers
would stop matching the artefact that is supposed to justify them.

## Do not regenerate the CA unless you have to

`CA.crt` is copied into places that do not update themselves: the APK, the Pi,
the operator credential and the VPP database. Regenerating it invalidates
every existing certificate. The full recovery order is the appendix of
[RUNBOOK.md](RUNBOOK.md).
