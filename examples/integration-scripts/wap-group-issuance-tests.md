# WAP Group Issuance E2E Tests

End-to-end tests for the WAP (Wallet Action Protocol) group issuance flow, focusing on out-of-order KERIA event processing and IPEX credential delivery.

## What it tests

Simulates a credential server (CS) sending `/wap/iss` to a 2-of-2 multisig group (M1+M2). Both members co-sign the VCP registry creation and credential issuance. G1 then sends `/exn/wap/iss/ack` back to CS. Test 6 extends this with IPEX grant/admit: G1 grants the issued credential to Holder.

Actors:
- **M1**: group member 1 (initiator — receives `/wap/iss`, builds VCP+ISS chain, submits ACK with both sigs)
- **M2**: group member 2 (cosigner — co-signs VCP+ISS via correlationId, contributes ACK sig)
- **G1**: 2-of-2 multisig group (M1+M2)
- **CS**: credential server (sends `/wap/iss`, receives ACK)
- **Holder**: IPEX grant recipient (test 6 only)

## Files involved

### Tests
- `examples/integration-scripts/wap-group-issuance-oor.test.ts` — 6 tests in one suite:
  1. **out-of-order**: all events submitted before any committed, two concurrent flows, CS receives two ACKs
  2. **explicit reverse**: M1 sends sn=4..1, M2 co-signs VCPs(2→1) then ISS(4→3), KERIA cascades both pairs
  3. **VCP2→VCP1→ISS2→ISS1**: M1 pre-computes full chain, writes sn+digest to disk, sends in that order
  4. **multi-cred OOR**: flow1 issues 1 cred, flow2 issues 3 creds — 8-event chain with 4-deep cascade
  5. **super-chaotic OOR**: 1 shared registry per flow, VCPs and ISS fully interleaved, M2 zigzag ISS order triggers 3-deep cascade
  6. **IPEX grant/admit**: standard single-flow issuance followed by G1 granting to Holder and Holder admitting back to G1

### Setup scripts (run before the tests)
- `examples/integration-scripts/utils/create-test-clients.ts` — bootstraps 4 fresh agents with random brans
- `examples/integration-scripts/utils/create-test-multisig.ts` — resolves M1↔M2 OOBIs, creates G1v2
- `examples/integration-scripts/utils/create-test-contacts.ts` — resolves OOBIs between all participants, registers G1's M1 agent endpoint on CS
- `examples/integration-scripts/utils/setup-all.ts` — orchestrator that runs the three above in order

### Generated state (gitignored)
- `examples/.test-clients.json` — 4 client brans + AIDs + agent EIDs
- `examples/.test-group.json` — G1 prefix + OOBI (via M1 agent)
- `examples/.test-contacts.json` — resolved contacts per client
- `examples/.test-oor3-chain.json` — pre-computed sn+digest chain for test 3
- `examples/.test-oor4-chain.json` — pre-computed sn+digest chain for test 4
- `examples/.test-oor5-chain.json` — pre-computed sn+digest chain for test 5

## Quick start

```bash
# 1. Wipe KERIA volume + restart (from PRIVATE-veridian-wallet/)
docker-compose down -v && docker-compose up -d

# 2. Generate setup state (from signify-ts/)
cd signify-ts
npx tsx examples/integration-scripts/utils/setup-all.ts

# 3. Run all 6 tests
npx jest examples/integration-scripts/wap-group-issuance-oor.test.ts --runInBand

# Or run only one test by name fragment
npx jest examples/integration-scripts/wap-group-issuance-oor.test.ts --runInBand -t "IPEX grant"
```

`--runInBand` is required — tests share KERIA state and must run in order.

## When to wipe the volume

`docker-compose down` (without `-v`) keeps the `keria-data` volume intact.

You **must** wipe the volume (`-v` flag) when:

- The previous test failed mid-flow (M1 sent VCP but M2 never co-signed). KERIA accumulates orphan registry events in its escrow and gets stuck in a loop processing them. The HTTP API stops responding.
- You're starting clean and want a deterministic state.
- KERIA's logs show repeated `Tevery unescrow error: Missing escrowed anchor`.
- `curl http://127.0.0.1:3901/spec.yaml` times out.

You can **skip** the volume wipe when:

- The previous full run passed. State stays consistent.
- You're only re-running setup to refresh test state (setup-all.ts deletes its own stale JSONs).

## Detailed workflow

### Step 1 — Wipe KERIA volume + restart

```bash
docker-compose down -v && docker-compose up -d
```

Wait for KERIA to be ready:

```bash
until curl -s --max-time 2 http://127.0.0.1:3901/spec.yaml > /dev/null; do sleep 1; done
```

The `cred-issuance` schema service needs a few extra seconds. Sleep 5–10 more just to be safe.

### Step 2 — Generate setup state

```bash
cd signify-ts
npx tsx examples/integration-scripts/utils/setup-all.ts
```

Runs three scripts in sequence:

1. **create-test-clients.ts** (~10 s):
   - Generates 4 random brans
   - For each: boots a KERIA agent, creates the identifier (`m1`/`m2`/`cs`/`holder`), registers the agent endRole
   - Writes `.test-clients.json` with bran/controller/agent/prefix/oobi per client

2. **create-test-multisig.ts** (~10 s):
   - Loads clients from `.test-clients.json`
   - Resolves M1↔M2 OOBIs (needed before sending `/multisig/icp`)
   - Creates G1v2 with isith=nsith=2, 3 witnesses
   - Registers agent endRoles for both members on the group
   - Writes `.test-group.json` with the G1 prefix and OOBI (via M1 agent endpoint)

3. **create-test-contacts.ts** (~30–60 s):
   - Resolves OOBIs between M1, M2, CS, Holder, and the schema server
   - Resolves G1's OOBI on CS using **M1's agent EID explicitly** (so KERIA delivers `/wap/iss` to M1, not M2)
   - Writes `.test-contacts.json` summary

Each run produces fresh AIDs because brans are random. If any script fails, the pipeline aborts and `setup-all.ts` exits non-zero.

### Step 3 — Run the tests

```bash
npx jest examples/integration-scripts/wap-group-issuance-oor.test.ts --runInBand
```

All 6 tests run in the same suite in order. They share the KERIA state set up in step 2.

### Step 4 — Cleanup between runs

If the test **passed**:

```bash
npx tsx examples/integration-scripts/utils/setup-all.ts
npx jest examples/integration-scripts/wap-group-issuance-oor.test.ts --runInBand
```

If the test **failed mid-flow**:

```bash
docker-compose down -v && docker-compose up -d
npx tsx examples/integration-scripts/utils/setup-all.ts
npx jest examples/integration-scripts/wap-group-issuance-oor.test.ts --runInBand
```

## Grouped KEL chain (tests 1–5)

All OOR tests use a **grouped chain** where all VCPs precede all ISS events:

```
ixn(X+1) = VCP1 anchor
ixn(X+2) = VCP2 anchor  (anchorPoint = { sn: X+1, d: vcp1Ixn.d })
ixn(X+3) = ISS1 anchor  (anchorPoint = { sn: X+2, d: vcp2Ixn.d })
ixn(X+4) = ISS2 anchor  (anchorPoint = { sn: X+3, d: iss1Ixn.d })
```

Grouping VCPs before ISS is required because KERIA's `credentials().issue()` endpoint rejects with 404 if `regk not in agent.rgy.regs` (`credentialing.py:664`). The registry only enters `regs` after its VCP commits. Interleaving VCP and ISS would create a race where ISS2 is submitted before VCP2 has cascaded.

M1 pre-computes the full chain upfront and submits all events without waiting for ops. KERIA buffers out-of-sequence events in escrow and cascades automatically once each prior event commits.

## Test 6 — IPEX grant/admit

Standard single-flow issuance (one VCP, one credential) followed by:

1. **M1 fetches** the committed credential from KERIA (`credentials().get(credSaid)`).
2. **G1 (M1+M2) grants** to Holder via IPEX. Both members call `ipex().grant()` with the same parameters and the same `datetime` so their signatures bind to the same exn SAID. M1 submits with combined sigs:
   ```typescript
   const [[grantExn, m1GrSigs, grantAtc], [, m2GrSigs]] = await Promise.all([
       m1Client.ipex().grant({ senderName: "G1v2", ancAttachment: m1Cred.ancatc, ... }),
       m2Client.ipex().grant({ senderName: "G1v2", ancAttachment: m1Cred.ancatc, ... }),
   ]);
   await m1Client.ipex().submitGrant("G1v2", grantExn, [...m1GrSigs, ...m2GrSigs], grantAtc, [holderPrefix]);
   ```
   The `ancAttachment` is reused from the issuance — it already carries the 2/2 G1 IXN signatures, so `ipex().grant()` doesn't re-sign the already-committed anchor.
3. **Holder admits** back to G1 (`recipient: g1Prefix`). KERIA stores the credential asynchronously once it resolves G1's key state from the witnesses and finds the schema in cache.
4. **Poll** `holderClient.credentials().list()` until the credential appears (up to 90 s, KERIA's Tevers resolution can take ~60 s).

Why CS cannot do the grant: KERIA's `Granter.recur()` calls `self.rgy.reger.creds.get(keys=(credSaid,))` to fetch the credential from the grant sender's registry (`agenting.py`). CS is not a G1 member and never received the credential, so this returns `None` → `AttributeError: 'NoneType' object has no attribute 'issuer'`. Only M1/G1 can grant what G1 issued.

## Key learnings (gotchas)

### 1. KERIA stores only one delivery endpoint per AID

`oobis().get("G1v2", "agent")` returns the **last-registered** agent endpoint for the group (typically M2's). If CS resolves that OOBI, KERIA delivers `/wap/iss` to M2, not M1.

`create-test-contacts.ts` constructs the G1 OOBI URL explicitly with M1's agent EID:

```
http://keria:3902/oobi/{G1_PREFIX}/agent/{M1_AGENT_EID}
```

This guarantees `/wap/iss` lands in M1's inbox.

### 2. `/multisig/*` exchanges use a different store

For `/exn/wap/iss`, `client.exchanges().get(said)` works directly.

For `/multisig/vcp` / `/multisig/iss` (sent via `exchanges().send()` to a group member), use:

```typescript
const req = await client.groups().getRequest(said);
const exn = req[0].exn;
```

### 3. Stuck escrow loops corrupt KERIA

When M1 sends a VCP anchor and M2 never co-signs, KERIA holds the ISS event in escrow retrying forever. Symptoms:

```
keri: Tevery unescrow error: Missing anchor at.dig = b'EGAVy...'
```

Only fix: `docker-compose down -v`.

### 4. Group ACK requires combined sigs in a single submission

Each KERIA agent has its own isolated LMDB database (`hby`). Sending two separate `/multisig/exn` wrappers (one from M1, one from M2) does NOT work — each agent ends up with only its own partial sig and neither reaches threshold.

Both members generate their sig locally (same params → same SAID), then M1 submits with BOTH sigs in one call:

```typescript
const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
    m1Client.exchanges().createExchangeMessage(g1HabM1, "/wap/iss/ack", ...),
    m2Client.exchanges().createExchangeMessage(g1HabM2, "/wap/iss/ack", ...),
]);
await m1Client.exchanges().sendFromEvents("G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]);
```

The same pattern applies to multisig IPEX grant (test 6).

### 5. Schema OOBI must use the Docker-internal hostname for KERIA

KERIA fetches the schema itself when processing an IPEX admit. The URL must be reachable from inside the Docker network:

- **Correct**: `http://cred-issuance:3001/oobi/{SCHEMA_SAID}`
- **Wrong**: `http://vlei-server:7723/oobi/...` (different Docker network, unreachable from KERIA)

For local runs (host-side scripts), use `http://localhost:3001` instead.

### 6. Notification pagination

`notifications().list()` defaults to `start=0, end=24` (25 oldest notifications). After accumulated test runs, new notifications fall past index 24 and become invisible. The test uses `list(0, 1000)` everywhere to avoid this.

### 7. `regk not in agent.rgy.regs` guard for ISS

`credentialing.py:664`:
```python
regk = iserder.ked['ri']
if regk not in agent.rgy.regs:
    raise falcon.HTTPNotFound(description=f"issue against invalid registry SAID {regk}")
```

M2 must wait for VCP to commit before calling `credentials().issue()`. M1 can skip this because it pre-queues VCP+ISS together in the same request batch before either commits — KERIA holds ISS in escrow and processes it once the VCP cascades.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Setup hangs on `client.boot()` or `client.connect()` | KERIA stuck (escrow loop) | `docker-compose down -v && docker-compose up -d` |
| Test fails with `Clients file not found` | `setup-all.ts` not run | Run `npx tsx ... setup-all.ts` |
| Test fails with `Contacts missing` | G1 OOBI resolution failed in setup | Wipe volume, retry setup |
| Test fails at `waitForNotifications /exn/wap/iss` (M1) | KERIA delivered to M2 instead | Verify `create-test-contacts.ts` used M1's agent EID for G1 OOBI |
| `credentials().issue()` returns 404 | Registry not committed when ISS submitted | M2 must wait for VCP op; use grouped chain (all VCPs before ISS) |
| CS never receives `/exn/wap/iss/ack` | ACK submitted with only one sig | Both sigs must be submitted in one call from M1 |
| Holder never receives `/exn/ipex/grant` | Holder hasn't resolved G1's OOBI | Test 6 setup resolves holder→G1 OOBI on first run |
| Holder credential never appears after admit | Schema not in KERIA cache or G1 key state not in Tevers | Schema OOBI must use `cred-issuance:3001`; poll up to 90 s |
| IPEX grant crashes KERIA with `AttributeError: 'NoneType' has no attribute 'issuer'` | Grant sender (CS) doesn't own the credential | Use G1 (M1+M2) as grant sender, not CS |
| `curl http://127.0.0.1:3901/spec.yaml` times out | KERIA HTTP API blocked by escrow loop | Wipe volume |
