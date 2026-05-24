# WAP Group Issuance E2E Tests

End-to-end test for the WAP (Wallet Action Protocol) group issuance flow.

## What it tests

Simulates a credential server (CS) sending `/wap/iss` to a 2-of-2 multisig group (M1+M2), with both members co-signing the VCP registry creation and credential issuance, and KERIA delivering an `/exn/wap/iss/ack` back to CS.

Actors:
- **M1**: group member 1 (initiator — receives `/wap/iss`, builds VCP+ISS, submits ACK with both sigs)
- **M2**: group member 2 (cosigner — co-signs VCP+ISS via correlationId, contributes ACK sig)
- **G1**: 2-of-2 multisig group (M1+M2)
- **CS**: credential server (sends `/wap/iss`)
- **Alice**: holder

## Files involved

### Tests
- `examples/integration-scripts/wap-group-issuance.test.ts` — parallel test (M1+M2 flows run concurrently)
- `examples/integration-scripts/wap-group-issuance-ordered.test.ts` — ordered test (VCP then ISS then ACK in strict sequence)
- `examples/integration-scripts/wap-group-issuance-ordered-multi.test.ts` — multi-flow ordered test (CS sends two concurrent `/wap/iss`; M1 chains VCP1/ISS1/VCP2/ISS2 with explicit anchorPoints; CS receives two ACKs)

### Setup scripts (run before the tests)
- `examples/integration-scripts/utils/create-test-clients.ts` — bootstraps 4 fresh agents with random brans
- `examples/integration-scripts/utils/create-test-multisig.ts` — resolves M1↔M2 OOBIs, creates G1v2
- `examples/integration-scripts/utils/create-test-contacts.ts` — resolves OOBIs between all participants, registers G1's M1 agent endpoint on CS
- `examples/integration-scripts/utils/setup-all.ts` — orchestrator that runs the three above in order

### Generated state (gitignored)
- `examples/.test-clients.json` — 4 client brans + AIDs + agent EIDs
- `examples/.test-group.json` — G1 prefix + OOBIs
- `examples/.test-contacts.json` — resolved contacts per client

## Quick start

From the repo root:

```bash
# 1. Wipe KERIA volume + restart
docker-compose down -v && docker-compose up -d
sleep 10

# 2. Generate setup state
npm run test:wap-e2e:setup

# 3. Run the test (parallel, ordered, or multi-flow)
npm run test:wap-e2e
npm run test:wap-e2e:ordered
npm run test:wap-e2e:multi
```

## When to wipe the volume

`docker-compose down` (without `-v`) keeps the `keria-data` volume intact.

You **must** wipe the volume (`-v` flag) when:

- The previous test failed mid-flow (M1 sent VCP but M2 never co-signed). KERIA accumulates orphan registry events in its escrow and gets stuck in a loop processing them. The HTTP API stops responding, every new request hangs.
- You're starting clean and want a deterministic state.
- KERIA's logs show repeated `Tevery unescrow failed: Missing escrowed anchor` or `Verifier unescrow failed: registry identifier ... not in Tevers`.
- `curl http://127.0.0.1:3901/spec.yaml` times out.

You can **skip** the volume wipe when:

- The previous test passed end-to-end. State stays consistent.
- You're only re-running setup to refresh test state (the setup deletes its own stale JSONs).

## Detailed workflow

### Step 1 — Wipe KERIA volume + restart

```bash
docker-compose down -v && docker-compose up -d
```

The `-v` removes the `keria-data` volume. Without it, KERIA reuses old state and the next test will fail with stuck escrow loops.

Wait for KERIA to be ready:

```bash
until curl -s --max-time 2 http://127.0.0.1:3901/spec.yaml > /dev/null; do
    sleep 1
done
```

The `cred-issuance` schema service needs a few extra seconds. Sleep 5–10 more just to be safe.

### Step 2 — Generate setup state

```bash
npm run test:wap-e2e:setup
```

Runs three scripts in sequence:

1. **create-test-clients.ts** (~10 s):
   - Generates 4 random brans
   - For each: boots a KERIA agent, creates the identifier (`m1`/`m2`/`cs`/`alice`), registers the agent endRole
   - Writes `.test-clients.json` with bran/controller/agent/prefix/oobi per client

2. **create-test-multisig.ts** (~10 s):
   - Loads clients from `.test-clients.json`
   - Resolves M1↔M2 OOBIs (needed before sending `/multisig/icp`)
   - Creates G1v2 with isith=nsith=2, 3 witnesses
   - Registers agent endRoles for both members on the group
   - Writes `.test-group.json` with the G1 prefix and OOBIs

3. **create-test-contacts.ts** (~30–60 s):
   - Resolves OOBIs between M1, M2, CS, Alice, and the schema server
   - Resolves G1's OOBI on CS using **M1's agent EID explicitly** (so KERIA delivers `/wap/iss` to M1, not M2 — see "Key learnings" below)
   - Writes `.test-contacts.json` summary

Each run produces fresh AIDs because brans are random in `create-test-clients.ts`.

If any of the three scripts fails, the pipeline aborts and `setup-all.ts` exits non-zero.

`setup-all.ts` also deletes the three JSONs at the start so a partial run doesn't leave stale state.

### Step 3 — Run the test

```bash
npm run test:wap-e2e          # parallel test
npm run test:wap-e2e:ordered  # ordered test
```

Both tests share the same setup state. The parallel test runs M1 and M2 flows concurrently; the ordered test runs VCP, ISS, and ACK phases in strict sequence.

Both tests:
1. Load the four clients from `.test-clients.json`
2. Load identifiers and the group from existing KERIA state
3. Sanity-check that contacts are mutually resolved (fails fast if setup didn't run)
4. Drive the flow:
   - CS sends `/wap/iss` to G1
   - M1 receives `/exn/wap/iss`, creates VCP, issues credentials, sends `/multisig/vcp` + `/multisig/iss`
   - M2 co-signs each
   - Both M1 and M2 generate their ACK sig (same params → same SAID)
   - M1 submits the ACK with BOTH sigs in a single call to M1's agent
   - KERIA sees 2/2 threshold met immediately → `WapackSender` fires on M1 → delivers ACK + artifacts to CS
5. Assert CS receives the ACK notification

### Step 4 — Cleanup between runs

If the test **passed**:

```bash
npm run test:wap-e2e:setup   # regenerates state with new AIDs
npm run test:wap-e2e
```

If the test **failed mid-flow**:

```bash
docker-compose down -v && docker-compose up -d
sleep 10
npm run test:wap-e2e:setup
npm run test:wap-e2e
```

A failed test almost always leaves KERIA stuck. The volume wipe is the only reliable reset.

## Key learnings (gotchas)

### 1. KERIA stores only one delivery endpoint per AID

`oobis().get("G1v2", "agent")` returns the **last-registered** agent endpoint for the group (typically M2's, since end roles are added in order M1→M2). If CS resolves that OOBI, KERIA delivers `/wap/iss` to M2, not M1.

`create-test-contacts.ts` constructs the G1 OOBI URL **explicitly** with M1's agent EID:

```
http://keria:3902/oobi/{G1_PREFIX}/agent/{M1_AGENT_EID}
```

This guarantees `/wap/iss` lands in M1's inbox, making M1 the consistent initiator.

### 2. `/multisig/*` exchanges use a different store

For routes like `/exn/wap/iss`, the recipient's notification's `a.d` is the exchange SAID and `client.exchanges().get(said)` works.

For `/multisig/vcp` / `/multisig/iss` (sent via `exchanges().send()` to a group member), the recipient's `a.d` points to a **group request**, not a regular exchange. Use:

```typescript
const req = await client.groups().getRequest(said);
const exn = req[0].exn;
```

The test's `pollExchangesByNotif` helper switches between the two based on the route prefix.

### 3. Stuck escrow loops corrupt KERIA

When M1 sends a VCP anchor and M2 never co-signs (failed test), KERIA holds the iss event in escrow waiting for the registry. The escrow processor retries forever, blocking the HTTP API. Symptoms:

```
keri: Tevery unescrow error: Missing anchor at.dig = b'EGAVy...'
keri: Tevery unescrow failed: Local event regk=EGAVy... when nonlocal mode
```

Only fix: `docker-compose down -v`.

### 4. KERIA agents are recreated each setup

`getOrCreateClient` patterns won't help when brans are random. After `down -v`, the agents are gone and the saved brans no longer correspond to any agent. The test's `getClientFromFile` handles this by attempting `connect()` and falling back to `boot()` if the agent doesn't exist.

Since `create-test-clients.ts` always generates fresh random brans, every setup produces brand-new agents and identifiers. There's no risk of mixing old and new state in a single client.

### 5. Schema fetch happens inside KERIA's network

The schema OOBI is `http://cred-issuance:3001/oobi/...` (Docker hostname). KERIA itself fetches it; host-side scripts only pass the URL through. Don't try to `curl` it from the host — the connection is reset if you don't send the right `Accept` header.

### 6. Group ACK requires combined sigs in a single submission

Each KERIA agent has its own isolated LMDB database (`hby`). The partial-sig escrow (`hby.db.esigs`) only merges signatures that arrive in a single `psr.parseOne` call. There is no automatic cross-agent sig propagation.

For a 2-of-2 group ACK exchange:
- Sending two separate `/multisig/exn` wrappers (one from M1, one from M2) does NOT work. Each agent ends up with only its own partial sig. Neither reaches threshold. `WapackSender` never fires.
- The IPEX-specific endpoints (`/ipex/admit`, `/ipex/grant`) have explicit code to extract and re-parse embedded sigs from the outer wrapper — but `ExchangeCollectionEnd` (the generic exchange endpoint) does not.

The correct approach: both members generate their ACK sig locally (using the same params → same SAID), then M1 submits with BOTH sigs in one call:

```typescript
const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
    m1Client.exchanges().createExchangeMessage(g1HabM1, "/wap/iss/ack", ...),
    m2Client.exchanges().createExchangeMessage(g1HabM2, "/wap/iss/ack", ...),
]);
await m1Client.exchanges().sendFromEvents("G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]);
```

KERIA sees 2/2 threshold immediately → exchange in `exns` → `complete()=true`, `lead()=true` for M1 (index 0 = M1's key) → `WapackSender` delivers to CS.

## npm scripts (defined in package.json)

```jsonc
{
  "test:wap-e2e:setup": "cd signify-ts && TEST_ENVIRONMENT=local npx tsx examples/integration-scripts/utils/setup-all.ts",
  "test:wap-e2e": "cd signify-ts && TEST_ENVIRONMENT=local npx jest examples/integration-scripts/wap-group-issuance.test.ts --testTimeout=300000 --verbose",
  "test:wap-e2e:ordered": "cd signify-ts && TEST_ENVIRONMENT=local npx jest examples/integration-scripts/wap-group-issuance-ordered.test.ts --testTimeout=300000 --verbose",
  "test:wap-e2e:multi": "cd signify-ts && TEST_ENVIRONMENT=local npx jest examples/integration-scripts/wap-group-issuance-ordered-multi.test.ts --testTimeout=300000 --verbose"
}
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Setup hangs on `client.boot()` or `client.connect()` | KERIA stuck (escrow loop) | `docker-compose down -v && docker-compose up -d` |
| Test fails with `Clients file not found` | `setup-all.ts` not run | `npm run test:wap-e2e:setup` |
| Test fails with `Contacts missing (csG1=false ...)` | G1 OOBI resolution failed in setup | Wipe volume, retry setup |
| Test fails at `waitForNotifications /exn/wap/iss` (M1) | KERIA delivered to M2 instead | Verify `create-test-contacts.ts` used M1's agent EID for G1 OOBI |
| Test fails at `pollExchangesByNotif /multisig/vcp` | M2 never received M1's exchange | Check M1 and M2 are mutual contacts; verify the test sees M2's `/multisig/vcp` notification |
| CS never receives `/exn/wap/iss/ack` | ACK submitted with only one sig | Both sigs must be submitted in one call from M1 (see gotcha 6) |
| Multi test hangs at `pollNextUnprocessed` | M1 still waiting for op, exchange not sent yet | Normal — M1 sends each exchange after the previous op completes; M2 retries until it appears |
| Multi test: second ACK never arrives at CS | First ACK consumed the only wapacks entry | Each flow's ACK has a distinct `p` field (corrId) → distinct SAID → separate wapacks entries |
| `curl http://127.0.0.1:3901/spec.yaml` times out | KERIA HTTP API blocked by escrow loop | Wipe volume |
