/**
 * E2E test: WAP group issuance — truly out-of-order delivery.
 *
 * Neither M1 nor M2 wait for operations to complete before proceeding.
 * M1 calculates the full anchorPoint chain upfront (sn=1..4) and submits
 * all four KEL ixn events to KERIA before any of them are committed.
 * M2 receives all four multisig exchanges at once, processes them concurrently
 * (all four co-sign submissions fire in parallel), then waits for all ops.
 * KERIA buffers out-of-sequence events in escrow and processes the cascade
 * automatically once each prior event is committed.
 *
 * Why this is harder:
 *   - KERIA receives ixn(sn=2..4) before ixn(sn=1) is committed → out-of-sequence escrow
 *   - M2's partial sigs for sn=2..4 arrive at KERIA before sn=1..3 are committed
 *   - KERIA must cascade: commit sn=1 → unescrow sn=2 → commit → unescrow sn=3 → ...
 *   - Two concurrent issuance flows, one registry each
 *
 * Both tests use the same GROUPED KEL chain (group starts at sn X):
 *   ixn(X+1) = VCP1 anchor
 *   ixn(X+2) = VCP2 anchor  (anchorPoint = { sn: X+1, d: vcp1Ixn.d })
 *   ixn(X+3) = ISS1 anchor  (anchorPoint = { sn: X+2, d: vcp2Ixn.d })
 *   ixn(X+4) = ISS2 anchor  (anchorPoint = { sn: X+3, d: iss1Ixn.d })
 * Grouped (all VCPs before all ISS) is required because KERIA's credentials().issue() checks
 * registry existence at submission time. Interleaved would cause a 404 race condition for ISS2
 * when VCP2 hasn't cascaded yet.
 *
 * Test 2 — explicit reverse: M1 sends ISS2→ISS1→VCP2→VCP1. M2 co-signs VCPs(2→1) then ISS(4→3).
 *
 * Test 3 — explicit VCP2→VCP1→ISS2→ISS1 order:
 * M1 pre-computes the full chain upfront (no op waiting), writes sn+digest for every event to disk
 * as JSON, then sends exchanges in the exact order VCP2→VCP1→ISS2→ISS1. M2 mirrors that order.
 * When VCP2 (sn+2) arrives at KERIA before VCP1 (sn+1), KERIA puts VCP2 on hold. When VCP1
 * arrives, KERIA commits sn+1 and cascades: sn+2 was waiting → commits immediately. Same cascade
 * for ISS2(sn+4) → ISS1(sn+3) → cascade fires ISS2. M1 persists the chain to
 * examples/.test-oor3-chain.json to demonstrate offline pre-computation of sn+digest.
 *
 * Test 4 — multi-cred OOR (one registry per credential): flow1 issues 1 cred, flow2 issues 3 creds:
 * 8-event grouped chain — 4 VCPs (sn+1..sn+4) then 4 ISS (sn+5..sn+8). M1 pre-computes all 8
 * sn+digest values, writes them to examples/.test-oor4-chain.json, then sends all VCPs in
 * descending sn order (sn+4→sn+3→sn+2→sn+1) and all ISS in descending sn order
 * (sn+8→sn+7→sn+6→sn+5). M2 co-signs in the same descending order per phase. KERIA holds
 * sn+2..sn+4 in psces until sn+1 commits then cascades all 3; same for the ISS group.
 * Demonstrates that KERIA can cascade a 4-deep escrow chain in both VCP and ISS phases.
 *
 * Test 5 — super-chaotic OOR: 1 shared registry per flow, VCPs and ISS fully interleaved:
 * 2 flows × 3 creds = 2 VCPs + 6 ISS = 8 ixn events. Only 2 registries (one per flow); all
 * credentials within a flow share that registry's ri. M1 pre-computes all 8 sn+digests, then
 * sends in a fully chaotic order where VCPs and ISS are interleaved:
 *   ISS_f2c2(sn+7) → VCP_f2(sn+2) → ISS_f1c3(sn+5) → ISS_f2c3(sn+8)
 *   → VCP_f1(sn+1) → ISS_f1c2(sn+4) → ISS_f2c1(sn+6) → ISS_f1c1(sn+3)
 * M2 filters VCPs out of the mixed exchange stream and co-signs them first (descending sn),
 * waits for the VCP cascade to commit both registries, then co-signs ISS in zigzag order
 * (alternating highest/lowest: sn+8→sn+3→sn+7→sn+4→sn+6→sn+5). The zigzag produces:
 * two immediate commits (sn+3, sn+4) then sn+5 triggers a 3-deep cascade (sn+6→sn+7→sn+8).
 * Chain state written to examples/.test-oor5-chain.json.
 *
 * Prerequisites:
 *   docker-compose down -v && docker-compose up -d
 *   npm run test:wap-e2e:setup
 */

import {
    b,
    d,
    Ident,
    Ilks,
    messagize,
    MtrDex,
    Prefixer,
    randomNonce,
    Saider,
    Serder,
    Serials,
    Siger,
    SignifyClient,
    Tier,
    versify,
    ready,
} from "signify-ts";
import { resolveEnvironment } from "./utils/resolve-env";
import { waitOperation } from "./utils/test-util";
import fs from "fs";
import path from "path";

const SCHEMA_SAID = "EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb";

function computeRegk(issuerAid: string, nonce: string): string {
    const vVersion = versify(Ident.KERI, undefined, Serials.JSON, 0);
    const vcp: Record<string, unknown> = {
        v: vVersion,
        t: Ilks.vcp,
        d: "",
        i: "",
        ii: issuerAid,
        s: "0",
        c: ["NB"],
        bt: "0",
        b: [],
        n: nonce,
    };
    return new Prefixer({ code: MtrDex.Blake3_256 }, vcp).qb64;
}

function signifyDatetime(): string {
    return new Date().toISOString().replace("Z", "000+00:00");
}

function buildRegistryEmbed(regResult: any): Record<string, any> {
    const sigers = regResult.sigs.map((sig: string) => new Siger({ qb64: sig }));
    const ims = d(messagize(regResult.serder, sigers));
    const atc = ims.substring(regResult.serder.size);
    return { vcp: [regResult.regser, ""], anc: [regResult.serder, atc] };
}

async function buildCredentialEmbed(
    client: SignifyClient,
    gHab: any,
    issResult: any
): Promise<Record<string, any>> {
    const keeper = client.manager!.get(gHab);
    const sigs = await keeper.sign(b(issResult.anc.raw));
    const sigers = sigs.map((s: string) => new Siger({ qb64: s }));
    const ims = d(messagize(issResult.anc, sigers));
    const atc = ims.substring(issResult.anc.size);
    return {
        acdc: [issResult.acdc, ""],
        iss: [issResult.iss, ""],
        anc: [issResult.anc, atc],
    };
}

async function getClientFromFile(name: string): Promise<SignifyClient> {
    const filePath = path.join(__dirname, "../../examples/.test-clients.json");
    const clientsData = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    const data = clientsData[name];
    if (!data) throw new Error(`Client ${name} not found in .test-clients.json`);
    const clientEnv = resolveEnvironment();
    await ready();
    const client = new SignifyClient(clientEnv.url, data.bran, Tier.low, clientEnv.bootUrl);
    try {
        await client.connect();
    } catch {
        await client.boot();
        await client.connect();
    }
    return client;
}

async function waitForNotificationsCount(
    client: SignifyClient,
    route: string,
    minCount: number,
    timeoutMs = 60000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const res = await client.notifications().list(0, 1000);
        const notes = (res.notes ?? []).filter(
            (n: any) => n.a.r === route && n.r === false
        );
        if (notes.length >= minCount) return notes;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`Timeout: waited for ${minCount} notifications route=${route}`);
}

// Polls until exactly `totalCount` exchanges from M1 are visible in M2's exchange list
// across both corrIds (excludes M2's own outgoing exchanges by sender prefix).
async function pollAllIncomingExchanges(
    client: SignifyClient,
    corrIds: string[],
    excludeSender: string,
    totalCount: number,
    timeoutMs = 90000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    let attempt = 0;
    while (Date.now() < deadline) {
        const all: any[] = [];
        for (const route of ["/multisig/vcp", "/multisig/iss"]) {
            let raw: any[] = [];
            try {
                raw = (await Promise.race([
                    client.exchanges().list({ filter: { "-r": route }, limit: 200 }),
                    new Promise<any[]>((_, rej) =>
                        setTimeout(() => rej(new Error("list timeout")), 10000)
                    ),
                ])) ?? [];
            } catch {
                // retry on timeout
            }
            const filtered = raw.filter(
                (x: any) =>
                    corrIds.includes(x.exn.a?.correlationId) &&
                    x.exn.i !== excludeSender
            );
            all.push(...filtered);
        }
        if (attempt % 5 === 0 || all.length >= totalCount) {
            console.log(
                "[POLL] attempt=%d found=%d want=%d",
                attempt, all.length, totalCount
            );
        }
        if (all.length >= totalCount) return all;
        attempt++;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout: waited for ${totalCount} incoming exchanges (corrIds=[${corrIds.join(",")}])`
    );
}

const clientsPath = path.join(__dirname, "../../examples/.test-clients.json");
const groupPath = path.join(__dirname, "../../examples/.test-group.json");

describe("WAP group issuance E2E (out-of-order, two concurrent flows)", () => {
    const env = resolveEnvironment();

    let m1Client: SignifyClient;
    let m2Client: SignifyClient;
    let csClient: SignifyClient;
    let holderClient: SignifyClient;

    let m1Hab: any;
    let m2Hab: any;
    let csHab: any;
    let holderHab: any;
    let g1HabM1: any;
    let g1HabM2: any;

    beforeAll(async () => {
        if (!fs.existsSync(clientsPath)) {
            throw new Error(
                `Clients file not found. Run setup first:\n  npm run test:wap-e2e:setup`
            );
        }
        if (!fs.existsSync(groupPath)) {
            throw new Error(
                `Group file not found. Run setup first:\n  npm run test:wap-e2e:setup`
            );
        }
        void env;

        console.log("[SETUP] Connecting clients...");
        [m1Client, m2Client, csClient, holderClient] = await Promise.all([
            getClientFromFile("m1"),
            getClientFromFile("m2"),
            getClientFromFile("cs"),
            getClientFromFile("holder"),
        ]);
        [m1Hab, m2Hab, csHab, holderHab, g1HabM1, g1HabM2] = await Promise.all([
            m1Client.identifiers().get("m1"),
            m2Client.identifiers().get("m2"),
            csClient.identifiers().get("cs"),
            holderClient.identifiers().get("holder"),
            m1Client.identifiers().get("G1v2"),
            m2Client.identifiers().get("G1v2"),
        ]);
        console.log("[SETUP] m1=%s G1=%s", m1Hab.prefix, g1HabM1.prefix);

        const [csG1, m1Cs, m2Cs] = await Promise.all([
            csClient.contacts().get(g1HabM1.prefix).catch(() => null),
            m1Client.contacts().get(csHab.prefix).catch(() => null),
            m2Client.contacts().get(csHab.prefix).catch(() => null),
        ]);
        if (!csG1 || !m1Cs || !m2Cs) {
            throw new Error(
                `Contacts missing (csG1=${!!csG1} m1Cs=${!!m1Cs} m2Cs=${!!m2Cs}). Re-run setup.`
            );
        }

        console.log("[SETUP] Contacts ok");
    }, 60000);

    // Mark any leftover unread notes before each test to prevent cross-test and cross-run pollution.
    // Runs before EACH test so a first-test failure can't leak its unread notes into the second test.
    beforeEach(async () => {
        const [m1NotesAll, csNotesAll] = await Promise.all([
            m1Client.notifications().list(0, 1000),
            csClient.notifications().list(0, 1000),
        ]);
        const leftoverM1 = (m1NotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/wap/iss" && n.r === false
        );
        const leftoverCs = (csNotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/wap/iss/ack" && n.r === false
        );
        await Promise.all([
            ...leftoverM1.map((n: any) => m1Client.notifications().mark(n.i)),
            ...leftoverCs.map((n: any) => csClient.notifications().mark(n.i)),
        ]);
        if (leftoverM1.length || leftoverCs.length) {
            console.log("[BEFORE EACH] Cleared %d M1 notes, %d CS notes",
                leftoverM1.length, leftoverCs.length);
        }
    }, 30000);

    it("out-of-order: all events submitted before any committed — CS receives two /exn/wap/iss/ack", async () => {
        const nonce1 = randomNonce();
        const nonce2 = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOR Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOR Flow2",
        })[1];
        const acdcSad2 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2,
            s: SCHEMA_SAID, a: aBlock2,
        })[1];

        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();

        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce1, l: [acdcSad1] }, {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce2, l: [acdcSad2] }, {}, g1Prefix, wapIssDt2
            ),
        ]);
        const csExn1Said = csExn1.ked.d;
        const csExn2Said = csExn2.ked.d;

        await Promise.all([
            csClient.exchanges().sendFromEvents("cs", "iss", csExn1, csSigs1, csAtc1, [g1Prefix]),
            csClient.exchanges().sendFromEvents("cs", "iss", csExn2, csSigs2, csAtc2, [g1Prefix]),
        ]);
        console.log("[CS] sent /wap/iss flow1=%s flow2=%s", csExn1Said, csExn2Said);

        // ── M1 waits for both /exn/wap/iss notifications ──────────────────────
        const m1Notes = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 2, 30000);
        const [exchA, exchB] = await Promise.all([
            m1Client.exchanges().get(m1Notes[0].a.d!),
            m1Client.exchanges().get(m1Notes[1].a.d!),
        ]);
        let req1: any, note1: any, req2: any, note2: any;
        if (exchA.exn.d === csExn1Said) {
            [req1, note1, req2, note2] = [exchA, m1Notes[0], exchB, m1Notes[1]];
        } else {
            [req1, note1, req2, note2] = [exchB, m1Notes[1], exchA, m1Notes[0]];
        }
        const corrId1: string = req1.exn.d;
        const corrId2: string = req2.exn.d;
        expect(corrId1).toBe(csExn1Said);
        expect(corrId2).toBe(csExn2Said);

        const payload1 = req1.exn.a as { n: string; l: any[] };
        const payload2 = req2.exn.a as { n: string; l: any[] };
        const cred1 = payload1.l[0];
        const cred2 = payload2.l[0];
        const issParams1 = {
            i: g1Prefix, ri: regk1, s: cred1.s, a: cred1.a,
            ...(cred1.u ? { u: cred1.u } : {}),
        };
        const issParams2 = {
            i: g1Prefix, ri: regk2, s: cred2.s, a: cred2.a,
            ...(cred2.u ? { u: cred2.u } : {}),
        };

        console.log("[TEST] Starting out-of-order phase — M1 chains without waiting, M2 two-phase concurrent");

        await Promise.all([
            // ── M1: build grouped chain sn=1..4 without waiting for any op ──────
            // Chain: VCP1(sn+1) → VCP2(sn+2) → ISS1(sn+3) → ISS2(sn+4)
            // KERIA receives higher-sn events before lower-sn are committed → escrows them.
            (async () => {
                // VCP1 — uses current group state as prior
                const regResult1 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce1}`,
                    nonce: nonce1,
                });
                const vcp1IxnSn = parseInt(regResult1.serder.ked.s, 16);
                const vcp1IxnSaid = regResult1.serder.ked.d;
                console.log("[M1] VCP1 queued: ixnSn=%d (op NOT awaited)", vcp1IxnSn);

                // VCP2 — anchorPoint = VCP1 ixn (grouped: both VCPs before any ISS)
                const regResult2 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce2}`,
                    nonce: nonce2,
                    anchorPoint: { sn: vcp1IxnSn, d: vcp1IxnSaid },
                });
                const vcp2IxnSn = parseInt(regResult2.serder.ked.s, 16);
                const vcp2IxnSaid = regResult2.serder.ked.d;
                console.log("[M1] VCP2 queued: ixnSn=%d anchored-after-VCP1(sn=%d) (op NOT awaited)", vcp2IxnSn, vcp1IxnSn);

                // ISS1 — anchorPoint = VCP2 ixn (not yet committed in KERIA)
                const iss1Result = await m1Client.credentials().issue(
                    "G1v2", issParams1, { sn: vcp2IxnSn, d: vcp2IxnSaid }
                );
                const iss1AncSn = iss1Result.anc.sn;
                const iss1AncSaid = iss1Result.anc.ked.d;
                console.log("[M1] ISS1 queued: ixnSn=%d (op NOT awaited)", iss1AncSn);

                // ISS2 — anchorPoint = ISS1 ixn (not yet committed in KERIA)
                const iss2Result = await m1Client.credentials().issue(
                    "G1v2", issParams2, { sn: iss1AncSn, d: iss1AncSaid }
                );
                console.log("[M1] ISS2 queued: ixnSn=%d (op NOT awaited)", iss2Result.anc.sn);
                console.log("[M1] grouped chain queued: KERIA has sn=1..4 (VCP1, VCP2, ISS1, ISS2) in escrow");

                // Build all embeds (local signing, no KERIA state needed)
                const [vcpEmbed1, vcpEmbed2, issEmbed1, issEmbed2] = await Promise.all([
                    Promise.resolve(buildRegistryEmbed(regResult1)),
                    Promise.resolve(buildRegistryEmbed(regResult2)),
                    buildCredentialEmbed(m1Client, g1HabM1, iss1Result),
                    buildCredentialEmbed(m1Client, g1HabM1, iss2Result),
                ]);

                // Fire all 4 multisig exchanges to M2 simultaneously
                await Promise.all([
                    m1Client.exchanges().send(
                        "m1", "registry", m1Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId1 },
                        vcpEmbed1, [m2Hab.prefix]
                    ),
                    m1Client.exchanges().send(
                        "m1", "multisig", m1Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId1 },
                        issEmbed1, [m2Hab.prefix]
                    ),
                    m1Client.exchanges().send(
                        "m1", "registry", m1Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId2 },
                        vcpEmbed2, [m2Hab.prefix]
                    ),
                    m1Client.exchanges().send(
                        "m1", "multisig", m1Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId2 },
                        issEmbed2, [m2Hab.prefix]
                    ),
                ]);
                console.log("[M1] all 4 multisig exchanges sent — now waiting for all ops");

                // Wait for all 4 ops — KERIA's escrow cascade completes them in sn order
                await Promise.all([
                    waitOperation(m1Client, await regResult1.op()),
                    waitOperation(m1Client, await regResult2.op()),
                    waitOperation(m1Client, iss1Result.op),
                    waitOperation(m1Client, iss2Result.op),
                ]);
                console.log("[M1] all 4 ops done");
            })(),

            // ── M2: wait for all 4 exchanges, co-sign VCPs concurrently, then ISS concurrently ──
            // Two-phase because M2's KERIA checks ri in Tevers when credentials().issue() is called —
            // registry only exists there after VCP commits. M1 skips this: its KERIA tracks pending VCPs locally.
            // Within each phase, both co-signs fire simultaneously so KERIA may receive sn+2
            // before sn+1 is committed (genuine OOR) — KERIA's psces escrow handles this.
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 4
                );

                const vcpExchanges = allExchanges.filter((e: any) => e.exn.r === "/multisig/vcp");
                const issExchanges = allExchanges.filter((e: any) => e.exn.r === "/multisig/iss");

                console.log(
                    "[M2] got all 4 exchanges: %d VCPs + %d ISS — co-signing concurrent per phase",
                    vcpExchanges.length, issExchanges.length
                );

                // Phase 1: co-sign both VCPs concurrently (sn+2 may arrive before sn+1 commits → OOR)
                const vcpOps = await Promise.all(
                    vcpExchanges.map(async (exchange: any) => {
                        const ancFull = exchange.exn.e?.anc as { s: string; p: string };
                        const targetSn = parseInt(ancFull.s, 16);
                        const anchorPoint = { sn: targetSn - 1, d: ancFull.p };
                        const corrId = exchange.exn.a?.correlationId as string;
                        const nonce = corrId === corrId1 ? nonce1 : nonce2;

                        const m2Reg = await m2Client.registries().create({
                            name: "G1v2", registryName: `wap-registry-${nonce}`, nonce, anchorPoint,
                        });
                        await m2Client.exchanges().send(
                            "m2", "registry", m2Hab, "/multisig/vcp",
                            { gid: g1Prefix, correlationId: corrId },
                            buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                        );
                        console.log("[M2] VCP co-sign queued: sn=%d (concurrent — KERIA may escrow)", targetSn);
                        return m2Reg.op();
                    })
                );

                // wait here — M2's KERIA must have ri in Tevers before credentials().issue() can be called
                await Promise.all(vcpOps.map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] both VCPs committed — starting ISS phase");

                // Phase 2: co-sign both ISS concurrently (sn+4 may arrive before sn+3 commits → OOR)
                const issOps = await Promise.all(
                    issExchanges.map(async (exchange: any) => {
                        const ancFull = exchange.exn.e?.anc as { s: string; p: string };
                        const targetSn = parseInt(ancFull.s, 16);
                        const anchorPoint = { sn: targetSn - 1, d: ancFull.p };
                        const corrId = exchange.exn.a?.correlationId as string;
                        const acdc = exchange.exn.e?.acdc as Record<string, unknown>;
                        const iss = exchange.exn.e?.iss as { ri: string };

                        const m2Iss = await m2Client.credentials().issue("G1v2", {
                            i: g1Prefix,
                            ri: iss.ri,
                            s: acdc.s as string,
                            a: acdc.a as Record<string, unknown>,
                            ...(acdc.u ? { u: acdc.u as string } : {}),
                        }, anchorPoint);
                        const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                        await m2Client.exchanges().send(
                            "m2", "multisig", m2Hab, "/multisig/iss",
                            { gid: g1Prefix, correlationId: corrId },
                            issEmbed, [m1Hab.prefix]
                        );
                        console.log("[M2] ISS co-sign queued: sn=%d (concurrent — KERIA may escrow)", targetSn);
                        return m2Iss.op;
                    })
                );

                console.log("[M2] all co-signs sent — waiting for KERIA escrow cascade");
                await Promise.all(issOps.map((op) => waitOperation(m2Client, op)));
                console.log("[M2] all 4 ops done");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
                m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
                m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
            ]);
            await m1Client.exchanges().sendFromEvents(
                "G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]
            );
            console.log("[M1] ACK submitted: said=%s corrId=...%s", ackExn.ked.d, req.exn.d.slice(-8));
            await m1Client.notifications().mark(note.i);
        }

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 90000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
            await csClient.notifications().mark(note.i);
        }
    }, 300000);

    it("explicit reverse-order: grouped chain VCP1→VCP2→ISS1→ISS2, M1 sends sn=4..1, M2 co-signs VCPs(2→1) then ISS(4→3) — KERIA cascades both pairs", async () => {
        const nonce1 = randomNonce();
        const nonce2 = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder ReverseOOR Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder ReverseOOR Flow2",
        })[1];
        const acdcSad2 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2,
            s: SCHEMA_SAID, a: aBlock2,
        })[1];

        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();

        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce1, l: [acdcSad1] }, {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce2, l: [acdcSad2] }, {}, g1Prefix, wapIssDt2
            ),
        ]);
        const csExn1Said = csExn1.ked.d;
        const csExn2Said = csExn2.ked.d;

        await Promise.all([
            csClient.exchanges().sendFromEvents("cs", "iss", csExn1, csSigs1, csAtc1, [g1Prefix]),
            csClient.exchanges().sendFromEvents("cs", "iss", csExn2, csSigs2, csAtc2, [g1Prefix]),
        ]);
        console.log("[CS] sent /wap/iss flow1=%s flow2=%s", csExn1Said, csExn2Said);

        // ── M1 waits for both notifications ───────────────────────────────────
        const m1Notes = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 2, 30000);
        const [exchA, exchB] = await Promise.all([
            m1Client.exchanges().get(m1Notes[0].a.d!),
            m1Client.exchanges().get(m1Notes[1].a.d!),
        ]);
        let req1: any, note1: any, req2: any, note2: any;
        if (exchA.exn.d === csExn1Said) {
            [req1, note1, req2, note2] = [exchA, m1Notes[0], exchB, m1Notes[1]];
        } else {
            [req1, note1, req2, note2] = [exchB, m1Notes[1], exchA, m1Notes[0]];
        }
        const corrId1: string = req1.exn.d;
        const corrId2: string = req2.exn.d;
        expect(corrId1).toBe(csExn1Said);
        expect(corrId2).toBe(csExn2Said);

        const payload1 = req1.exn.a as { n: string; l: any[] };
        const payload2 = req2.exn.a as { n: string; l: any[] };
        const cred1 = payload1.l[0];
        const cred2 = payload2.l[0];
        const issParams1 = {
            i: g1Prefix, ri: regk1, s: cred1.s, a: cred1.a,
            ...(cred1.u ? { u: cred1.u } : {}),
        };
        const issParams2 = {
            i: g1Prefix, ri: regk2, s: cred2.s, a: cred2.a,
            ...(cred2.u ? { u: cred2.u } : {}),
        };

        console.log("[TEST] Explicit reverse OOR — grouped chain VCP1→VCP2→ISS1→ISS2, sent in reverse sn=4..1");

        await Promise.all([
            // ── M1: build GROUPED chain, send in REVERSE sn order: sn+4→sn+3→sn+2→sn+1 ──
            (async () => {
                // VCP1 at sn+1
                const regResult1 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce1}`,
                    nonce: nonce1,
                });
                const vcp1IxnSn = parseInt(regResult1.serder.ked.s, 16);
                const vcp1IxnSaid = regResult1.serder.ked.d;

                // VCP2 at sn+2, anchored after VCP1 (both VCPs before any ISS)
                const regResult2 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce2}`,
                    nonce: nonce2,
                    anchorPoint: { sn: vcp1IxnSn, d: vcp1IxnSaid },
                });
                const vcp2IxnSn = parseInt(regResult2.serder.ked.s, 16);
                const vcp2IxnSaid = regResult2.serder.ked.d;

                // ISS1 at sn+3, anchored after VCP2
                const iss1Result = await m1Client.credentials().issue(
                    "G1v2", issParams1, { sn: vcp2IxnSn, d: vcp2IxnSaid }
                );
                const iss1AncSn = iss1Result.anc.sn;
                const iss1AncSaid = iss1Result.anc.ked.d;

                // ISS2 at sn+4, anchored after ISS1
                const iss2Result = await m1Client.credentials().issue(
                    "G1v2", issParams2, { sn: iss1AncSn, d: iss1AncSaid }
                );

                console.log(
                    "[M1] grouped chain: VCP1(sn=%d) VCP2(sn=%d) ISS1(sn=%d) ISS2(sn=%d)",
                    vcp1IxnSn, vcp2IxnSn, iss1AncSn, iss2Result.anc.sn
                );

                const [vcpEmbed1, vcpEmbed2, issEmbed1, issEmbed2] = await Promise.all([
                    Promise.resolve(buildRegistryEmbed(regResult1)),
                    Promise.resolve(buildRegistryEmbed(regResult2)),
                    buildCredentialEmbed(m1Client, g1HabM1, iss1Result),
                    buildCredentialEmbed(m1Client, g1HabM1, iss2Result),
                ]);

                // Send in STRICT REVERSE sn order: ISS2(sn+4) → ISS1(sn+3) → VCP2(sn+2) → VCP1(sn+1)
                console.log("[M1] sending in reverse: %d→%d→%d→%d",
                    iss2Result.anc.sn, iss1AncSn, vcp2IxnSn, vcp1IxnSn);

                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 },
                    issEmbed2, [m2Hab.prefix]  // sn+4 — sent first
                );
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 },
                    issEmbed1, [m2Hab.prefix]  // sn+3
                );
                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 },
                    vcpEmbed2, [m2Hab.prefix]  // sn+2
                );
                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 },
                    vcpEmbed1, [m2Hab.prefix]  // sn+1 — sent last
                );
                console.log("[M1] all 4 exchanges sent in reverse — now waiting for ops");

                await Promise.all([
                    waitOperation(m1Client, await regResult1.op()),
                    waitOperation(m1Client, await regResult2.op()),
                    waitOperation(m1Client, iss1Result.op),
                    waitOperation(m1Client, iss2Result.op),
                ]);
                console.log("[M1] all 4 ops done");
            })(),

            // ── M2: wait for all 4, then co-sign in TWO REVERSED PHASES ──────
            // Phase 1 — VCPs reversed (VCP2→VCP1): KERIA escrows VCP2 until VCP1 commits
            //           → cascade commits both registries.
            // Wait for both VCP ops before phase 2 — M2's KERIA checks ri in Tevers when credentials().issue()
            // is called, and the registry only exists there after VCP commits. M1 skips this.
            // Phase 2 — ISS reversed (ISS2→ISS1): KERIA escrows ISS2 until ISS1 commits
            //           → cascade commits ISS2.
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 4
                );

                const vcpExchanges = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/vcp")
                    .sort((a: any, b: any) =>
                        parseInt(b.exn.e?.anc?.s ?? "0", 16) -
                        parseInt(a.exn.e?.anc?.s ?? "0", 16)  // descending: VCP2 first
                    );
                const issExchanges = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/iss")
                    .sort((a: any, b: any) =>
                        parseInt(b.exn.e?.anc?.s ?? "0", 16) -
                        parseInt(a.exn.e?.anc?.s ?? "0", 16)  // descending: ISS2 first
                    );

                console.log(
                    "[M2] VCP phase (reversed): %s — ISS phase (reversed): %s",
                    vcpExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→"),
                    issExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→")
                );

                // Phase 1: VCPs in reverse (VCP2 → VCP1), sequential
                const vcpOps: Array<Promise<any>> = [];
                for (const exchange of vcpExchanges) {
                    const ancFull = exchange.exn.e?.anc as { s: string; p: string };
                    const targetSn = parseInt(ancFull.s, 16);
                    const anchorPoint = { sn: targetSn - 1, d: ancFull.p };
                    const corrId = exchange.exn.a?.correlationId as string;
                    const nonce = corrId === corrId1 ? nonce1 : nonce2;

                    const m2Reg = await m2Client.registries().create({
                        name: "G1v2",
                        registryName: `wap-registry-${nonce}`,
                        nonce,
                        anchorPoint,
                    });
                    await m2Client.exchanges().send(
                        "m2", "registry", m2Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId },
                        buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                    );
                    console.log("[M2] VCP co-sign submitted sn=%d (KERIA holds in escrow until prior commits)", targetSn);
                    vcpOps.push(m2Reg.op());
                }

                // Wait for both VCP ops — cascade from VCP1 ensures VCP2 commits too
                await Promise.all(vcpOps.map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] both VCPs committed — registries available for ISS phase");

                // Phase 2: ISS in reverse (ISS2 → ISS1), sequential
                const issOps: Array<any> = [];
                for (const exchange of issExchanges) {
                    const ancFull = exchange.exn.e?.anc as { s: string; p: string };
                    const targetSn = parseInt(ancFull.s, 16);
                    const anchorPoint = { sn: targetSn - 1, d: ancFull.p };
                    const corrId = exchange.exn.a?.correlationId as string;
                    const acdc = exchange.exn.e?.acdc as Record<string, unknown>;
                    const iss = exchange.exn.e?.iss as { ri: string };

                    const m2Iss = await m2Client.credentials().issue("G1v2", {
                        i: g1Prefix,
                        ri: iss.ri,
                        s: acdc.s as string,
                        a: acdc.a as Record<string, unknown>,
                        ...(acdc.u ? { u: acdc.u as string } : {}),
                    }, anchorPoint);
                    const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                    await m2Client.exchanges().send(
                        "m2", "multisig", m2Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId },
                        issEmbed, [m1Hab.prefix]
                    );
                    console.log("[M2] ISS co-sign submitted sn=%d (KERIA holds in escrow until prior commits)", targetSn);
                    issOps.push(m2Iss.op);
                }

                await Promise.all(issOps.map((op) => waitOperation(m2Client, op)));
                console.log("[M2] all 4 ops done — cascade completed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
                m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
                m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
            ]);
            await m1Client.exchanges().sendFromEvents(
                "G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]
            );
            console.log("[M1] ACK submitted: said=%s corrId=...%s", ackExn.ked.d, req.exn.d.slice(-8));
            await m1Client.notifications().mark(note.i);
        }

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 90000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
            await csClient.notifications().mark(note.i);
        }
    }, 300000);

    it("explicit VCP2→VCP1→ISS2→ISS1: M1 pre-computes full chain, writes sn+digest to disk, sends in that order — KERIA holds VCP2 and ISS2 until their priors arrive then cascades", async () => {
        const nonce1 = randomNonce();
        const nonce2 = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOR3 Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];
        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOR3 Flow2",
        })[1];
        const acdcSad2 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2,
            s: SCHEMA_SAID, a: aBlock2,
        })[1];

        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();
        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce1, l: [acdcSad1] }, {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce2, l: [acdcSad2] }, {}, g1Prefix, wapIssDt2
            ),
        ]);
        const csExn1Said = csExn1.ked.d;
        const csExn2Said = csExn2.ked.d;
        await Promise.all([
            csClient.exchanges().sendFromEvents("cs", "iss", csExn1, csSigs1, csAtc1, [g1Prefix]),
            csClient.exchanges().sendFromEvents("cs", "iss", csExn2, csSigs2, csAtc2, [g1Prefix]),
        ]);
        console.log("[CS] sent /wap/iss flow1=%s flow2=%s", csExn1Said, csExn2Said);

        // ── M1 waits for both /exn/wap/iss notifications ──────────────────────
        const m1Notes = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 2, 30000);
        const [exchA, exchB] = await Promise.all([
            m1Client.exchanges().get(m1Notes[0].a.d!),
            m1Client.exchanges().get(m1Notes[1].a.d!),
        ]);
        let req1: any, note1: any, req2: any, note2: any;
        if (exchA.exn.d === csExn1Said) {
            [req1, note1, req2, note2] = [exchA, m1Notes[0], exchB, m1Notes[1]];
        } else {
            [req1, note1, req2, note2] = [exchB, m1Notes[1], exchA, m1Notes[0]];
        }
        const corrId1: string = req1.exn.d;
        const corrId2: string = req2.exn.d;
        expect(corrId1).toBe(csExn1Said);
        expect(corrId2).toBe(csExn2Said);

        const payload1 = req1.exn.a as { n: string; l: any[] };
        const payload2 = req2.exn.a as { n: string; l: any[] };
        const cred1 = payload1.l[0];
        const cred2 = payload2.l[0];
        const issParams1 = {
            i: g1Prefix, ri: regk1, s: cred1.s, a: cred1.a,
            ...(cred1.u ? { u: cred1.u } : {}),
        };
        const issParams2 = {
            i: g1Prefix, ri: regk2, s: cred2.s, a: cred2.a,
            ...(cred2.u ? { u: cred2.u } : {}),
        };

        // ── M1 pre-computes the full grouped chain upfront (no op waiting) ────
        // VCP1 at sn+1
        const regResult1 = await m1Client.registries().create({
            name: "G1v2",
            registryName: `wap-registry-${nonce1}`,
            nonce: nonce1,
        });
        const vcp1IxnSn = parseInt(regResult1.serder.ked.s, 16);
        const vcp1IxnSaid = regResult1.serder.ked.d;

        // VCP2 at sn+2, anchored after VCP1
        const regResult2 = await m1Client.registries().create({
            name: "G1v2",
            registryName: `wap-registry-${nonce2}`,
            nonce: nonce2,
            anchorPoint: { sn: vcp1IxnSn, d: vcp1IxnSaid },
        });
        const vcp2IxnSn = parseInt(regResult2.serder.ked.s, 16);
        const vcp2IxnSaid = regResult2.serder.ked.d;

        // ISS1 at sn+3, anchored after VCP2
        const iss1Result = await m1Client.credentials().issue(
            "G1v2", issParams1, { sn: vcp2IxnSn, d: vcp2IxnSaid }
        );
        const iss1AncSn = iss1Result.anc.sn;
        const iss1AncSaid = iss1Result.anc.ked.d;

        // ISS2 at sn+4, anchored after ISS1
        const iss2Result = await m1Client.credentials().issue(
            "G1v2", issParams2, { sn: iss1AncSn, d: iss1AncSaid }
        );

        console.log(
            "[M1] full chain pre-computed: VCP1(sn=%d) VCP2(sn=%d) ISS1(sn=%d) ISS2(sn=%d)",
            vcp1IxnSn, vcp2IxnSn, iss1AncSn, iss2Result.anc.sn
        );

        // Persist chain state — sn+digest for each event, computed before any exchange is sent
        const chainPath = path.join(__dirname, "../../examples/.test-oor3-chain.json");
        fs.writeFileSync(chainPath, JSON.stringify({
            testRun: new Date().toISOString(),
            g1Prefix,
            sendOrder: ["VCP2", "VCP1", "ISS2", "ISS1"],
            regk1,
            regk2,
            vcp1: { ixnSn: vcp1IxnSn, ixnSaid: vcp1IxnSaid },
            vcp2: { ixnSn: vcp2IxnSn, ixnSaid: vcp2IxnSaid },
            iss1: { ixnSn: iss1AncSn, ixnSaid: iss1AncSaid },
            iss2: { ixnSn: iss2Result.anc.sn, ixnSaid: iss2Result.anc.ked.d },
        }, null, 2));
        console.log("[M1] chain written to disk: %s", chainPath);

        // Build all embeds (local signing, no KERIA state needed)
        const [vcpEmbed1, vcpEmbed2, issEmbed1, issEmbed2] = await Promise.all([
            Promise.resolve(buildRegistryEmbed(regResult1)),
            Promise.resolve(buildRegistryEmbed(regResult2)),
            buildCredentialEmbed(m1Client, g1HabM1, iss1Result),
            buildCredentialEmbed(m1Client, g1HabM1, iss2Result),
        ]);

        console.log("[TEST] explicit VCP2→VCP1→ISS2→ISS1 — M1 and M2 follow that order");

        await Promise.all([
            // ── M1: send in VCP2→VCP1→ISS2→ISS1 order ──────────────────────────
            (async () => {
                console.log("[M1] sending: VCP2(sn=%d)→VCP1(sn=%d)→ISS2(sn=%d)→ISS1(sn=%d)",
                    vcp2IxnSn, vcp1IxnSn, iss2Result.anc.sn, iss1AncSn);

                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 },
                    vcpEmbed2, [m2Hab.prefix]   // VCP2 — sn+2 first
                );
                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 },
                    vcpEmbed1, [m2Hab.prefix]   // VCP1 — sn+1 second
                );
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 },
                    issEmbed2, [m2Hab.prefix]   // ISS2 — sn+4 third
                );
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 },
                    issEmbed1, [m2Hab.prefix]   // ISS1 — sn+3 last
                );
                console.log("[M1] all 4 exchanges sent in VCP2→VCP1→ISS2→ISS1 order — waiting for ops");

                await Promise.all([
                    waitOperation(m1Client, await regResult1.op()),
                    waitOperation(m1Client, await regResult2.op()),
                    waitOperation(m1Client, iss1Result.op),
                    waitOperation(m1Client, iss2Result.op),
                ]);
                console.log("[M1] all 4 ops done");
            })(),

            // ── M2: co-sign in VCP2→VCP1→ISS2→ISS1 order ───────────────────────
            // VCP2 (sn+2) arrives at KERIA before prior (sn+1) is committed → KERIA holds.
            // VCP1 (sn+1) arrives → 2/2 threshold met → commits → cascade unescrows VCP2 → commits.
            // Both registries exist after VCP2 op completes.
            // ISS2 (sn+4) → KERIA holds. ISS1 (sn+3) → commits → cascade → ISS2 commits.
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 4
                );

                const findExch = (route: string, corrId: string) =>
                    allExchanges.find((e: any) => e.exn.r === route && e.exn.a?.correlationId === corrId)!;
                const vcp2Exch = findExch("/multisig/vcp", corrId2);
                const vcp1Exch = findExch("/multisig/vcp", corrId1);
                const iss2Exch = findExch("/multisig/iss", corrId2);
                const iss1Exch = findExch("/multisig/iss", corrId1);

                const ancOf = (exchange: any) => {
                    const a = exchange.exn.e?.anc as { s: string; p: string };
                    return { anchorPoint: { sn: parseInt(a.s, 16) - 1, d: a.p }, sn: parseInt(a.s, 16) };
                };

                console.log("[M2] got all 4 — co-signing in VCP2→VCP1→ISS2→ISS1 order");

                // VCP2 (sn+2): KERIA holds — prior (sn+1) not committed yet
                const { anchorPoint: vcp2Ap, sn: vcp2Sn } = ancOf(vcp2Exch);
                const m2Reg2 = await m2Client.registries().create({
                    name: "G1v2", registryName: `wap-registry-${nonce2}`,
                    nonce: nonce2, anchorPoint: vcp2Ap,
                });
                await m2Client.exchanges().send(
                    "m2", "registry", m2Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 },
                    buildRegistryEmbed(m2Reg2), [m1Hab.prefix]
                );
                console.log("[M2] VCP2 co-sign: sn=%d — KERIA holds (sn=%d not committed)", vcp2Sn, vcp2Sn - 1);
                const vcp2OpP = m2Reg2.op();

                // VCP1 (sn+1): 2/2 → commits → cascade unescrows VCP2 → both registries committed
                const { anchorPoint: vcp1Ap, sn: vcp1Sn } = ancOf(vcp1Exch);
                const m2Reg1 = await m2Client.registries().create({
                    name: "G1v2", registryName: `wap-registry-${nonce1}`,
                    nonce: nonce1, anchorPoint: vcp1Ap,
                });
                await m2Client.exchanges().send(
                    "m2", "registry", m2Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 },
                    buildRegistryEmbed(m2Reg1), [m1Hab.prefix]
                );
                console.log("[M2] VCP1 co-sign: sn=%d → 2/2 → commits → cascade unescrows VCP2", vcp1Sn);

                // Wait for VCP2 op — implies VCP1 committed + VCP2 cascaded → regk1+regk2 exist.
                // M2's KERIA checks ri in Tevers when credentials().issue() is called; M1 skips this.
                await waitOperation(m2Client, await vcp2OpP);
                console.log("[M2] VCP2 committed — regk1 and regk2 available");

                // ISS2 (sn+4): KERIA holds — prior (sn+3) not committed yet
                const { anchorPoint: iss2Ap, sn: iss2Sn } = ancOf(iss2Exch);
                const acdc2 = iss2Exch.exn.e?.acdc as Record<string, unknown>;
                const iss2Ev = iss2Exch.exn.e?.iss as { ri: string };
                const m2Iss2 = await m2Client.credentials().issue("G1v2", {
                    i: g1Prefix, ri: iss2Ev.ri,
                    s: acdc2.s as string, a: acdc2.a as Record<string, unknown>,
                    ...(acdc2.u ? { u: acdc2.u as string } : {}),
                }, iss2Ap);
                const iss2EmbedM2 = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss2);
                await m2Client.exchanges().send(
                    "m2", "multisig", m2Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 },
                    iss2EmbedM2, [m1Hab.prefix]
                );
                console.log("[M2] ISS2 co-sign: sn=%d — KERIA holds (sn=%d not committed)", iss2Sn, iss2Sn - 1);

                // ISS1 (sn+3): 2/2 → commits → cascade unescrows ISS2 → ISS2 commits
                const { anchorPoint: iss1Ap, sn: iss1Sn } = ancOf(iss1Exch);
                const acdc1 = iss1Exch.exn.e?.acdc as Record<string, unknown>;
                const iss1Ev = iss1Exch.exn.e?.iss as { ri: string };
                const m2Iss1 = await m2Client.credentials().issue("G1v2", {
                    i: g1Prefix, ri: iss1Ev.ri,
                    s: acdc1.s as string, a: acdc1.a as Record<string, unknown>,
                    ...(acdc1.u ? { u: acdc1.u as string } : {}),
                }, iss1Ap);
                const iss1EmbedM2 = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss1);
                await m2Client.exchanges().send(
                    "m2", "multisig", m2Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 },
                    iss1EmbedM2, [m1Hab.prefix]
                );
                console.log("[M2] ISS1 co-sign: sn=%d → 2/2 → commits → cascade unescrows ISS2", iss1Sn);

                await Promise.all([
                    waitOperation(m2Client, m2Iss2.op),
                    waitOperation(m2Client, m2Iss1.op),
                ]);
                console.log("[M2] all 4 ops done — cascade completed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
                m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
                m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
            ]);
            await m1Client.exchanges().sendFromEvents(
                "G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]
            );
            console.log("[M1] ACK submitted: said=%s corrId=...%s", ackExn.ked.d, req.exn.d.slice(-8));
            await m1Client.notifications().mark(note.i);
        }

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 90000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
            await csClient.notifications().mark(note.i);
        }
    }, 300000);

    it("multi-cred OOR: flow1 issues 1 cred, flow2 issues 3 creds — M1 pre-computes 8-event chain, sends all VCPs reversed then all ISS reversed — KERIA cascades both groups of 4", async () => {
        const [nonce1, nonce2, nonce3, nonce4] = [randomNonce(), randomNonce(), randomNonce(), randomNonce()];
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);
        const regk3 = computeRegk(g1Prefix, nonce3);
        const regk4 = computeRegk(g1Prefix, nonce4);

        // ── CS builds ACDCs: flow1 has 1 cred, flow2 has 3 creds ─────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({ d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOR4 Flow1 Cred1" })[1];
        const acdcSad1 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1, s: SCHEMA_SAID, a: aBlock1 })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({ d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOR4 Flow2 Cred1" })[1];
        const acdcSad2 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2, s: SCHEMA_SAID, a: aBlock2 })[1];

        const dt3 = signifyDatetime();
        const aBlock3 = Saider.saidify({ d: "", i: holderPrefix, dt: dt3, attendeeName: "Holder OOR4 Flow2 Cred2" })[1];
        const acdcSad3 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk3, s: SCHEMA_SAID, a: aBlock3 })[1];

        const dt4 = signifyDatetime();
        const aBlock4 = Saider.saidify({ d: "", i: holderPrefix, dt: dt4, attendeeName: "Holder OOR4 Flow2 Cred3" })[1];
        const acdcSad4 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk4, s: SCHEMA_SAID, a: aBlock4 })[1];

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();
        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce1, l: [acdcSad1] }, {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss", { n: nonce2, l: [acdcSad2, acdcSad3, acdcSad4] }, {}, g1Prefix, wapIssDt2
            ),
        ]);
        const csExn1Said = csExn1.ked.d;
        const csExn2Said = csExn2.ked.d;
        await Promise.all([
            csClient.exchanges().sendFromEvents("cs", "iss", csExn1, csSigs1, csAtc1, [g1Prefix]),
            csClient.exchanges().sendFromEvents("cs", "iss", csExn2, csSigs2, csAtc2, [g1Prefix]),
        ]);
        console.log("[CS] sent /wap/iss flow1(1 cred)=%s flow2(3 creds)=%s", csExn1Said, csExn2Said);

        // ── M1 waits for both /exn/wap/iss notifications ──────────────────────
        const m1Notes = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 2, 30000);
        const [exchA, exchB] = await Promise.all([
            m1Client.exchanges().get(m1Notes[0].a.d!),
            m1Client.exchanges().get(m1Notes[1].a.d!),
        ]);
        let req1: any, note1: any, req2: any, note2: any;
        if (exchA.exn.d === csExn1Said) {
            [req1, note1, req2, note2] = [exchA, m1Notes[0], exchB, m1Notes[1]];
        } else {
            [req1, note1, req2, note2] = [exchB, m1Notes[1], exchA, m1Notes[0]];
        }
        const corrId1: string = req1.exn.d;
        const corrId2: string = req2.exn.d;
        expect(corrId1).toBe(csExn1Said);
        expect(corrId2).toBe(csExn2Said);

        const payload1 = req1.exn.a as { n: string; l: any[] };
        const payload2 = req2.exn.a as { n: string; l: any[] };
        const [cred1] = payload1.l;
        const [cred2, cred3, cred4] = payload2.l;
        const issParams1 = { i: g1Prefix, ri: regk1, s: cred1.s, a: cred1.a, ...(cred1.u ? { u: cred1.u } : {}) };
        const issParams2 = { i: g1Prefix, ri: regk2, s: cred2.s, a: cred2.a, ...(cred2.u ? { u: cred2.u } : {}) };
        const issParams3 = { i: g1Prefix, ri: regk3, s: cred3.s, a: cred3.a, ...(cred3.u ? { u: cred3.u } : {}) };
        const issParams4 = { i: g1Prefix, ri: regk4, s: cred4.s, a: cred4.a, ...(cred4.u ? { u: cred4.u } : {}) };

        // ── M1 pre-computes 8-event grouped chain (no op waiting) ─────────────
        // VCP(f1c1) sn+1 → VCP(f2c1) sn+2 → VCP(f2c2) sn+3 → VCP(f2c3) sn+4
        // → ISS(f1c1) sn+5 → ISS(f2c1) sn+6 → ISS(f2c2) sn+7 → ISS(f2c3) sn+8
        const rr1 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-registry-${nonce1}`, nonce: nonce1 });
        const [sn1, d1] = [parseInt(rr1.serder.ked.s, 16), rr1.serder.ked.d];

        const rr2 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-registry-${nonce2}`, nonce: nonce2, anchorPoint: { sn: sn1, d: d1 } });
        const [sn2, d2] = [parseInt(rr2.serder.ked.s, 16), rr2.serder.ked.d];

        const rr3 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-registry-${nonce3}`, nonce: nonce3, anchorPoint: { sn: sn2, d: d2 } });
        const [sn3, d3] = [parseInt(rr3.serder.ked.s, 16), rr3.serder.ked.d];

        const rr4 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-registry-${nonce4}`, nonce: nonce4, anchorPoint: { sn: sn3, d: d3 } });
        const [sn4, d4] = [parseInt(rr4.serder.ked.s, 16), rr4.serder.ked.d];

        const ir1 = await m1Client.credentials().issue("G1v2", issParams1, { sn: sn4, d: d4 });
        const [sn5, d5] = [ir1.anc.sn, ir1.anc.ked.d];

        const ir2 = await m1Client.credentials().issue("G1v2", issParams2, { sn: sn5, d: d5 });
        const [sn6, d6] = [ir2.anc.sn, ir2.anc.ked.d];

        const ir3 = await m1Client.credentials().issue("G1v2", issParams3, { sn: sn6, d: d6 });
        const [sn7, d7] = [ir3.anc.sn, ir3.anc.ked.d];

        const ir4 = await m1Client.credentials().issue("G1v2", issParams4, { sn: sn7, d: d7 });

        console.log(
            "[M1] 8-event chain: VCP(f1c1,sn=%d) VCP(f2c1,sn=%d) VCP(f2c2,sn=%d) VCP(f2c3,sn=%d) ISS(f1c1,sn=%d) ISS(f2c1,sn=%d) ISS(f2c2,sn=%d) ISS(f2c3,sn=%d)",
            sn1, sn2, sn3, sn4, sn5, sn6, sn7, ir4.anc.sn
        );

        // Persist chain — all 8 sn+digest values computed before any exchange is sent
        const chainPath = path.join(__dirname, "../../examples/.test-oor4-chain.json");
        fs.writeFileSync(chainPath, JSON.stringify({
            testRun: new Date().toISOString(),
            g1Prefix,
            flow1: { nCredentials: 1 },
            flow2: { nCredentials: 3 },
            sendOrder: ["VCP_f2c3", "VCP_f2c2", "VCP_f2c1", "VCP_f1c1", "ISS_f2c3", "ISS_f2c2", "ISS_f2c1", "ISS_f1c1"],
            chain: [
                { pos: 1, type: "VCP", flow: 1, cred: 1, regk: regk1, ixnSn: sn1, ixnSaid: d1 },
                { pos: 2, type: "VCP", flow: 2, cred: 1, regk: regk2, ixnSn: sn2, ixnSaid: d2 },
                { pos: 3, type: "VCP", flow: 2, cred: 2, regk: regk3, ixnSn: sn3, ixnSaid: d3 },
                { pos: 4, type: "VCP", flow: 2, cred: 3, regk: regk4, ixnSn: sn4, ixnSaid: d4 },
                { pos: 5, type: "ISS", flow: 1, cred: 1, regk: regk1, ixnSn: sn5, ixnSaid: d5 },
                { pos: 6, type: "ISS", flow: 2, cred: 1, regk: regk2, ixnSn: sn6, ixnSaid: d6 },
                { pos: 7, type: "ISS", flow: 2, cred: 2, regk: regk3, ixnSn: sn7, ixnSaid: d7 },
                { pos: 8, type: "ISS", flow: 2, cred: 3, regk: regk4, ixnSn: ir4.anc.sn, ixnSaid: ir4.anc.ked.d },
            ],
        }, null, 2));
        console.log("[M1] 8-event chain written to disk: %s", chainPath);

        // Build all 8 embeds (local signing, no KERIA state needed)
        const [vcpEmbed1, vcpEmbed2, vcpEmbed3, vcpEmbed4, issEmbed1, issEmbed2, issEmbed3, issEmbed4] =
            await Promise.all([
                Promise.resolve(buildRegistryEmbed(rr1)),
                Promise.resolve(buildRegistryEmbed(rr2)),
                Promise.resolve(buildRegistryEmbed(rr3)),
                Promise.resolve(buildRegistryEmbed(rr4)),
                buildCredentialEmbed(m1Client, g1HabM1, ir1),
                buildCredentialEmbed(m1Client, g1HabM1, ir2),
                buildCredentialEmbed(m1Client, g1HabM1, ir3),
                buildCredentialEmbed(m1Client, g1HabM1, ir4),
            ]);

        console.log("[TEST] sending VCPs(sn=%d→%d→%d→%d) then ISS(sn=%d→%d→%d→%d)",
            sn4, sn3, sn2, sn1, ir4.anc.sn, sn7, sn6, sn5);

        await Promise.all([
            // ── M1: VCPs reversed (sn+4→sn+3→sn+2→sn+1) then ISS reversed (sn+8→sn+7→sn+6→sn+5) ──
            (async () => {
                // VCPs: highest sn first — sn+4 sits in KERIA escrow waiting for sn+3, etc.
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 }, vcpEmbed4, [m2Hab.prefix]);  // sn+4
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 }, vcpEmbed3, [m2Hab.prefix]);  // sn+3
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 }, vcpEmbed2, [m2Hab.prefix]);  // sn+2
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 }, vcpEmbed1, [m2Hab.prefix]);  // sn+1 — cascade trigger
                // ISS: highest sn first — sn+8 sits in escrow, sn+5 triggers 4-deep cascade
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmbed4, [m2Hab.prefix]);  // sn+8
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmbed3, [m2Hab.prefix]);  // sn+7
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmbed2, [m2Hab.prefix]);  // sn+6
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 }, issEmbed1, [m2Hab.prefix]);  // sn+5 — cascade trigger
                console.log("[M1] all 8 exchanges sent — waiting for ops");

                await Promise.all([
                    waitOperation(m1Client, await rr1.op()),
                    waitOperation(m1Client, await rr2.op()),
                    waitOperation(m1Client, await rr3.op()),
                    waitOperation(m1Client, await rr4.op()),
                    waitOperation(m1Client, ir1.op),
                    waitOperation(m1Client, ir2.op),
                    waitOperation(m1Client, ir3.op),
                    waitOperation(m1Client, ir4.op),
                ]);
                console.log("[M1] all 8 ops done");
            })(),

            // ── M2: poll 8 exchanges, co-sign VCPs reversed then ISS reversed ──
            // VCP phase: sn+4→sn+3→sn+2→sn+1 (sequential). KERIA holds sn+4..sn+2 in psces;
            // sn+1 triggers 3-deep cascade → all 4 registries committed.
            // ISS phase: sn+8→sn+7→sn+6→sn+5. Same cascade pattern → all 4 creds committed.
            // M2 extracts the nonce from exchange.exn.e.vcp.n (VCP event has n field).
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 8
                );

                const ancOf = (exchange: any) => {
                    const a = exchange.exn.e?.anc as { s: string; p: string };
                    return { anchorPoint: { sn: parseInt(a.s, 16) - 1, d: a.p }, sn: parseInt(a.s, 16) };
                };

                const vcpExchanges = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/vcp")
                    .sort((a: any, b: any) =>
                        parseInt(b.exn.e?.anc?.s ?? "0", 16) - parseInt(a.exn.e?.anc?.s ?? "0", 16)
                    );
                const issExchanges = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/iss")
                    .sort((a: any, b: any) =>
                        parseInt(b.exn.e?.anc?.s ?? "0", 16) - parseInt(a.exn.e?.anc?.s ?? "0", 16)
                    );

                console.log(
                    "[M2] got 8 exchanges — VCP order: %s — ISS order: %s",
                    vcpExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→"),
                    issExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→")
                );

                // VCP phase: descending sn (sn+4→sn+3→sn+2→sn+1)
                const vcpOpPromises: Array<Promise<any>> = [];
                for (const exchange of vcpExchanges) {
                    const { anchorPoint, sn } = ancOf(exchange);
                    const corrId = exchange.exn.a?.correlationId as string;
                    const nonce = (exchange.exn.e?.vcp as any)?.n as string;

                    const m2Reg = await m2Client.registries().create({
                        name: "G1v2", registryName: `wap-registry-${nonce}`, nonce, anchorPoint,
                    });
                    await m2Client.exchanges().send(
                        "m2", "registry", m2Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId },
                        buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                    );
                    console.log("[M2] VCP co-sign: sn=%d — KERIA holds until prior commits", sn);
                    vcpOpPromises.push(m2Reg.op());
                }

                // Wait for all VCP ops — sn+1 commits last in submission but first in cascade,
                // so sn+4 completing means full 4-deep cascade finished.
                // M2's KERIA checks ri in Tevers when credentials().issue() is called; M1 skips this.
                await Promise.all(vcpOpPromises.map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] VCP cascade complete — all 4 registries committed");

                // ISS phase: descending sn (sn+8→sn+7→sn+6→sn+5)
                const issOpPromises: Array<any> = [];
                for (const exchange of issExchanges) {
                    const { anchorPoint, sn } = ancOf(exchange);
                    const corrId = exchange.exn.a?.correlationId as string;
                    const acdc = exchange.exn.e?.acdc as Record<string, unknown>;
                    const iss = exchange.exn.e?.iss as { ri: string };

                    const m2Iss = await m2Client.credentials().issue("G1v2", {
                        i: g1Prefix, ri: iss.ri,
                        s: acdc.s as string, a: acdc.a as Record<string, unknown>,
                        ...(acdc.u ? { u: acdc.u as string } : {}),
                    }, anchorPoint);
                    const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                    await m2Client.exchanges().send(
                        "m2", "multisig", m2Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId },
                        issEmbed, [m1Hab.prefix]
                    );
                    console.log("[M2] ISS co-sign: sn=%d — KERIA holds until prior commits", sn);
                    issOpPromises.push(m2Iss.op);
                }

                await Promise.all(issOpPromises.map((op) => waitOperation(m2Client, op)));
                console.log("[M2] ISS cascade complete — all 4 credentials committed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
                m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
                m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
            ]);
            await m1Client.exchanges().sendFromEvents(
                "G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]
            );
            console.log("[M1] ACK submitted: said=%s corrId=...%s", ackExn.ked.d, req.exn.d.slice(-8));
            await m1Client.notifications().mark(note.i);
        }

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 90000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
            await csClient.notifications().mark(note.i);
        }
    }, 300000);

    it("super-chaotic OOR: 1 shared registry per flow, M1 interleaves VCPs and ISS freely — M2 zigzag ISS order triggers 3-deep cascade at sn+5", async () => {
        const [nonce1, nonce2] = [randomNonce(), randomNonce()];
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        // Only 2 registries: all creds within a flow share the same ri
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS builds ACDCs: flow1 (3 creds, all ri=regk1), flow2 (3 creds, all ri=regk2) ───
        const makeAcdc = (ri: string, name: string) => {
            const dt = signifyDatetime();
            const aBlock = Saider.saidify({ d: "", i: holderPrefix, dt, attendeeName: name })[1];
            return Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri, s: SCHEMA_SAID, a: aBlock })[1];
        };
        const acdcSad_f1c1 = makeAcdc(regk1, "Holder OOR5 Flow1 Cred1");
        const acdcSad_f1c2 = makeAcdc(regk1, "Holder OOR5 Flow1 Cred2");
        const acdcSad_f1c3 = makeAcdc(regk1, "Holder OOR5 Flow1 Cred3");
        const acdcSad_f2c1 = makeAcdc(regk2, "Holder OOR5 Flow2 Cred1");
        const acdcSad_f2c2 = makeAcdc(regk2, "Holder OOR5 Flow2 Cred2");
        const acdcSad_f2c3 = makeAcdc(regk2, "Holder OOR5 Flow2 Cred3");

        // ── CS sends two /wap/iss: flow1 (3 creds, 1 registry), flow2 (3 creds, 1 registry) ──
        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();
        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss",
                { n: nonce1, l: [acdcSad_f1c1, acdcSad_f1c2, acdcSad_f1c3] },
                {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss",
                { n: nonce2, l: [acdcSad_f2c1, acdcSad_f2c2, acdcSad_f2c3] },
                {}, g1Prefix, wapIssDt2
            ),
        ]);
        const csExn1Said = csExn1.ked.d;
        const csExn2Said = csExn2.ked.d;
        await Promise.all([
            csClient.exchanges().sendFromEvents("cs", "iss", csExn1, csSigs1, csAtc1, [g1Prefix]),
            csClient.exchanges().sendFromEvents("cs", "iss", csExn2, csSigs2, csAtc2, [g1Prefix]),
        ]);
        console.log("[CS] sent flow1(3 creds, regk1)=%s flow2(3 creds, regk2)=%s", csExn1Said, csExn2Said);

        // ── M1 waits for both /exn/wap/iss notifications ──────────────────────
        const m1Notes = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 2, 30000);
        const [exchA, exchB] = await Promise.all([
            m1Client.exchanges().get(m1Notes[0].a.d!),
            m1Client.exchanges().get(m1Notes[1].a.d!),
        ]);
        let req1: any, note1: any, req2: any, note2: any;
        if (exchA.exn.d === csExn1Said) {
            [req1, note1, req2, note2] = [exchA, m1Notes[0], exchB, m1Notes[1]];
        } else {
            [req1, note1, req2, note2] = [exchB, m1Notes[1], exchA, m1Notes[0]];
        }
        const corrId1: string = req1.exn.d;
        const corrId2: string = req2.exn.d;
        expect(corrId1).toBe(csExn1Said);
        expect(corrId2).toBe(csExn2Said);

        const [cred_f1c1, cred_f1c2, cred_f1c3] = (req1.exn.a as { l: any[] }).l;
        const [cred_f2c1, cred_f2c2, cred_f2c3] = (req2.exn.a as { l: any[] }).l;
        const mkIss = (ri: string, c: any) => ({ i: g1Prefix, ri, s: c.s, a: c.a, ...(c.u ? { u: c.u } : {}) });
        const issP_f1c1 = mkIss(regk1, cred_f1c1);
        const issP_f1c2 = mkIss(regk1, cred_f1c2);
        const issP_f1c3 = mkIss(regk1, cred_f1c3);
        const issP_f2c1 = mkIss(regk2, cred_f2c1);
        const issP_f2c2 = mkIss(regk2, cred_f2c2);
        const issP_f2c3 = mkIss(regk2, cred_f2c3);

        // ── M1 pre-computes 8-event grouped chain (no op waiting) ─────────────
        // 2 VCPs (one per flow), then 6 ISS (3 per flow, all sharing their flow's registry)
        // sn+1: VCP_f1   sn+2: VCP_f2
        // sn+3: ISS_f1c1   sn+4: ISS_f1c2   sn+5: ISS_f1c3
        // sn+6: ISS_f2c1   sn+7: ISS_f2c2   sn+8: ISS_f2c3
        const rr1 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-reg-${nonce1}`, nonce: nonce1 });
        const [sn1, d1] = [parseInt(rr1.serder.ked.s, 16), rr1.serder.ked.d];

        const rr2 = await m1Client.registries().create({ name: "G1v2", registryName: `wap-reg-${nonce2}`, nonce: nonce2, anchorPoint: { sn: sn1, d: d1 } });
        const [sn2, d2] = [parseInt(rr2.serder.ked.s, 16), rr2.serder.ked.d];

        const ir1 = await m1Client.credentials().issue("G1v2", issP_f1c1, { sn: sn2, d: d2 });
        const [sn3, d3] = [ir1.anc.sn, ir1.anc.ked.d];

        const ir2 = await m1Client.credentials().issue("G1v2", issP_f1c2, { sn: sn3, d: d3 });
        const [sn4, d4] = [ir2.anc.sn, ir2.anc.ked.d];

        const ir3 = await m1Client.credentials().issue("G1v2", issP_f1c3, { sn: sn4, d: d4 });
        const [sn5, d5] = [ir3.anc.sn, ir3.anc.ked.d];

        const ir4 = await m1Client.credentials().issue("G1v2", issP_f2c1, { sn: sn5, d: d5 });
        const [sn6, d6] = [ir4.anc.sn, ir4.anc.ked.d];

        const ir5 = await m1Client.credentials().issue("G1v2", issP_f2c2, { sn: sn6, d: d6 });
        const [sn7, d7] = [ir5.anc.sn, ir5.anc.ked.d];

        const ir6 = await m1Client.credentials().issue("G1v2", issP_f2c3, { sn: sn7, d: d7 });

        console.log(
            "[M1] 8-event chain: VCP_f1(sn=%d) VCP_f2(sn=%d) ISS_f1c1(sn=%d) ISS_f1c2(sn=%d) ISS_f1c3(sn=%d) ISS_f2c1(sn=%d) ISS_f2c2(sn=%d) ISS_f2c3(sn=%d)",
            sn1, sn2, sn3, sn4, sn5, sn6, sn7, ir6.anc.sn
        );

        // Persist chain — 2 shared registries + 6 ISS, computed before any exchange is sent
        const chainPath = path.join(__dirname, "../../examples/.test-oor5-chain.json");
        fs.writeFileSync(chainPath, JSON.stringify({
            testRun: new Date().toISOString(),
            g1Prefix,
            sharedRegistries: true,
            flow1: { nCredentials: 3, regk: regk1 },
            flow2: { nCredentials: 3, regk: regk2 },
            m1SendOrder: [sn7, sn2, sn5, ir6.anc.sn, sn1, sn4, sn6, sn3],
            m2IssZigzagOrder: [ir6.anc.sn, sn3, sn7, sn4, sn6, sn5],
            chain: [
                { pos: 1, type: "VCP", flow: 1, regk: regk1, ixnSn: sn1, ixnSaid: d1 },
                { pos: 2, type: "VCP", flow: 2, regk: regk2, ixnSn: sn2, ixnSaid: d2 },
                { pos: 3, type: "ISS", flow: 1, cred: 1, regk: regk1, ixnSn: sn3, ixnSaid: d3 },
                { pos: 4, type: "ISS", flow: 1, cred: 2, regk: regk1, ixnSn: sn4, ixnSaid: d4 },
                { pos: 5, type: "ISS", flow: 1, cred: 3, regk: regk1, ixnSn: sn5, ixnSaid: d5 },
                { pos: 6, type: "ISS", flow: 2, cred: 1, regk: regk2, ixnSn: sn6, ixnSaid: d6 },
                { pos: 7, type: "ISS", flow: 2, cred: 2, regk: regk2, ixnSn: sn7, ixnSaid: d7 },
                { pos: 8, type: "ISS", flow: 2, cred: 3, regk: regk2, ixnSn: ir6.anc.sn, ixnSaid: ir6.anc.ked.d },
            ],
        }, null, 2));
        console.log("[M1] chain written: %s", chainPath);

        // Build all 8 embeds
        const [vcpEmb1, vcpEmb2, issEmb1, issEmb2, issEmb3, issEmb4, issEmb5, issEmb6] =
            await Promise.all([
                Promise.resolve(buildRegistryEmbed(rr1)),
                Promise.resolve(buildRegistryEmbed(rr2)),
                buildCredentialEmbed(m1Client, g1HabM1, ir1),
                buildCredentialEmbed(m1Client, g1HabM1, ir2),
                buildCredentialEmbed(m1Client, g1HabM1, ir3),
                buildCredentialEmbed(m1Client, g1HabM1, ir4),
                buildCredentialEmbed(m1Client, g1HabM1, ir5),
                buildCredentialEmbed(m1Client, g1HabM1, ir6),
            ]);

        // M1 super-chaotic send order: ISS_f2c2(sn+7)→VCP_f2(sn+2)→ISS_f1c3(sn+5)→ISS_f2c3(sn+8)
        //                              →VCP_f1(sn+1)→ISS_f1c2(sn+4)→ISS_f2c1(sn+6)→ISS_f1c1(sn+3)
        // VCPs and ISS are fully interleaved. KERIA holds every event in psces until VCP sn+1
        // commits and cascades sn+2, then the ISS cascade resolves in two phases.
        console.log("[TEST] M1 send order: %d→%d→%d→%d→%d→%d→%d→%d",
            sn7, sn2, sn5, ir6.anc.sn, sn1, sn4, sn6, sn3);

        await Promise.all([
            // ── M1: fully interleaved send ────────────────────────────────────
            (async () => {
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmb5, [m2Hab.prefix]);  // ISS_f2c2 sn+7
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 }, vcpEmb2, [m2Hab.prefix]);  // VCP_f2 sn+2
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 }, issEmb3, [m2Hab.prefix]);  // ISS_f1c3 sn+5
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmb6, [m2Hab.prefix]);  // ISS_f2c3 sn+8
                await m1Client.exchanges().send("m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 }, vcpEmb1, [m2Hab.prefix]);  // VCP_f1 sn+1
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 }, issEmb2, [m2Hab.prefix]);  // ISS_f1c2 sn+4
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 }, issEmb4, [m2Hab.prefix]);  // ISS_f2c1 sn+6
                await m1Client.exchanges().send("m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 }, issEmb1, [m2Hab.prefix]);  // ISS_f1c1 sn+3
                console.log("[M1] all 8 exchanges sent in chaotic order — waiting for ops");

                await Promise.all([
                    waitOperation(m1Client, await rr1.op()),
                    waitOperation(m1Client, await rr2.op()),
                    waitOperation(m1Client, ir1.op),
                    waitOperation(m1Client, ir2.op),
                    waitOperation(m1Client, ir3.op),
                    waitOperation(m1Client, ir4.op),
                    waitOperation(m1Client, ir5.op),
                    waitOperation(m1Client, ir6.op),
                ]);
                console.log("[M1] all 8 ops done");
            })(),

            // ── M2: filter VCPs from mixed stream, co-sign VCPs first, then ISS zigzag ──
            // VCP phase (descending sn): sn+2 → sn+1.
            //   sn+2 has 2/2 but prior sn+1 not committed → psces.
            //   sn+1 commits → cascade sn+2. Both registries exist.
            //
            // ISS phase (zigzag — alternating highest/lowest sn from sorted list):
            //   [sn+8, sn+3, sn+7, sn+4, sn+6, sn+5]
            //   sn+8: 2/2, prior sn+7 not committed → psces
            //   sn+3: 2/2, prior sn+2 committed → COMMITS → cascade: sn+4 not 2/2 yet → stop
            //   sn+7: 2/2, prior sn+6 not committed → psces
            //   sn+4: 2/2, prior sn+3 committed → COMMITS → cascade: sn+5 not 2/2 yet → stop
            //   sn+6: 2/2, prior sn+5 not committed → psces
            //   sn+5: 2/2, prior sn+4 committed → COMMITS → cascade: sn+6→sn+7→sn+8 (3-deep!)
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 8
                );

                const ancOf = (e: any) => {
                    const a = e.exn.e?.anc as { s: string; p: string };
                    return { anchorPoint: { sn: parseInt(a.s, 16) - 1, d: a.p }, sn: parseInt(a.s, 16) };
                };
                const getSn = (e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16);

                // VCP phase: filter and sort descending
                const vcpExchanges = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/vcp")
                    .sort((a: any, b: any) => getSn(b) - getSn(a));

                console.log("[M2] VCP order (descending): %s",
                    vcpExchanges.map((e: any) => getSn(e)).join("→"));

                const vcpOpPromises: Array<Promise<any>> = [];
                for (const exchange of vcpExchanges) {
                    const { anchorPoint, sn } = ancOf(exchange);
                    const corrId = exchange.exn.a?.correlationId as string;
                    const nonce = (exchange.exn.e?.vcp as any)?.n as string;
                    const m2Reg = await m2Client.registries().create({
                        name: "G1v2", registryName: `wap-reg-${nonce}`, nonce, anchorPoint,
                    });
                    await m2Client.exchanges().send(
                        "m2", "registry", m2Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId },
                        buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                    );
                    console.log("[M2] VCP co-sign: sn=%d — KERIA holds until prior commits", sn);
                    vcpOpPromises.push(m2Reg.op());
                }

                // M2's KERIA checks ri in Tevers when credentials().issue() is called — registry only exists there after VCP commits. M1 skips this.
                await Promise.all(vcpOpPromises.map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] both registries committed (sn+1 cascade → sn+2)");

                // ISS phase: zigzag order (alternating highest/lowest from sorted list)
                // sorted asc: [sn+3, sn+4, sn+5, sn+6, sn+7, sn+8]
                // zigzag:     [sn+8, sn+3, sn+7, sn+4, sn+6, sn+5]
                const issAll = allExchanges
                    .filter((e: any) => e.exn.r === "/multisig/iss")
                    .sort((a: any, b: any) => getSn(a) - getSn(b));  // ascending
                const issZigzag: any[] = [];
                let lo = 0, hi = issAll.length - 1;
                while (lo <= hi) {
                    issZigzag.push(issAll[hi--]);
                    if (lo <= hi) issZigzag.push(issAll[lo++]);
                }

                console.log("[M2] ISS zigzag order: %s",
                    issZigzag.map((e: any) => getSn(e)).join("→"));

                const issOpPromises: Array<any> = [];
                for (const exchange of issZigzag) {
                    const { anchorPoint, sn } = ancOf(exchange);
                    const corrId = exchange.exn.a?.correlationId as string;
                    const acdc = exchange.exn.e?.acdc as Record<string, unknown>;
                    const iss = exchange.exn.e?.iss as { ri: string };

                    const m2Iss = await m2Client.credentials().issue("G1v2", {
                        i: g1Prefix, ri: iss.ri,
                        s: acdc.s as string, a: acdc.a as Record<string, unknown>,
                        ...(acdc.u ? { u: acdc.u as string } : {}),
                    }, anchorPoint);
                    const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                    await m2Client.exchanges().send(
                        "m2", "multisig", m2Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId },
                        issEmbed, [m1Hab.prefix]
                    );
                    console.log("[M2] ISS co-sign: sn=%d (ri=...%s)", sn, iss.ri.slice(-8));
                    issOpPromises.push(m2Iss.op);
                }

                await Promise.all(issOpPromises.map((op) => waitOperation(m2Client, op)));
                console.log("[M2] all 6 ISS ops done — 3-deep cascade from sn+5 completed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
                m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
                m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: req.exn.d },
                    {}, req.exn.i, req.exn.dt, req.exn.d
                ),
            ]);
            await m1Client.exchanges().sendFromEvents(
                "G1v2", "wap", ackExn, [...ackSigs1, ...ackSigs2], "", [csHab.prefix]
            );
            console.log("[M1] ACK submitted: said=%s corrId=...%s", ackExn.ked.d, req.exn.d.slice(-8));
            await m1Client.notifications().mark(note.i);
        }

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 90000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
            await csClient.notifications().mark(note.i);
        }
    }, 300000);

    it("IPEX grant/admit: G1 grants issued credential to holder", async () => {
        const nonce = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk = computeRegk(g1Prefix, nonce);

        // Holder needs CS, G1, and the schema resolved so KERIA can store the credential after admit.
        const [holderCs, holderG1] = await Promise.all([
            holderClient.contacts().get(csHab.prefix).catch(() => null),
            holderClient.contacts().get(g1Prefix).catch(() => null),
        ]);
        const m1OobiStr = (await m1Client.oobis().get("m1", "agent")).oobis[0] as string;
        const keriaBase = m1OobiStr.replace(/http:\/\/keria:/g, "http://127.0.0.1:").split("/oobi/")[0];
        const credServerBase = env.preset === "local" ? "http://localhost:3001" : "http://cred-issuance:3001";
        const schemaOobi = `${credServerBase}/oobi/${SCHEMA_SAID}`;
        // Resolve once per run; schema cache doesn't surface via contacts().list() but re-resolving is safe.
        await Promise.all([
            !holderCs
                ? holderClient.oobis()
                    .resolve(
                        (await csClient.oobis().get("cs", "agent")).oobis[0]
                            .replace(/http:\/\/keria:/g, "http://127.0.0.1:"),
                        "cs"
                    ).then((op: any) => waitOperation(holderClient, op))
                : Promise.resolve(),
            !holderG1
                ? holderClient.oobis()
                    .resolve(`${keriaBase}/oobi/${g1Prefix}/agent/${m1Client.agent!.pre}`, "G1v2")
                    .then((op: any) => waitOperation(holderClient, op))
                : Promise.resolve(),
            holderClient.oobis()
                .resolve(schemaOobi, "schema")
                .then((op: any) => waitOperation(holderClient, op))
                .catch(() => {}),
        ]);
        if (!holderCs || !holderG1) console.log("[SETUP] holder resolved missing OOBIs");

        // CS builds ACDC and sends /wap/iss
        const credDt = signifyDatetime();
        const aBlock = Saider.saidify({
            d: "", i: holderPrefix, dt: credDt, attendeeName: "Holder IPEX",
        })[1];
        const acdcSad = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk, s: SCHEMA_SAID, a: aBlock,
        })[1];
        const credSaid = acdcSad.d as string;

        const wapDt = signifyDatetime();
        const [csExn, csSigs, csAtc] = await csClient.exchanges().createExchangeMessage(
            csHab, "/wap/iss", { n: nonce, l: [acdcSad] }, {}, g1Prefix, wapDt
        );
        const csExnSaid = csExn.ked.d as string;
        await csClient.exchanges().sendFromEvents("cs", "iss", csExn, csSigs, csAtc, [g1Prefix]);
        console.log("[CS] sent /wap/iss said=%s cred=%s", csExnSaid, credSaid);

        // M1 waits for /exn/wap/iss
        const [m1Note] = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 1, 30000);
        const reqExn = await m1Client.exchanges().get(m1Note.a.d!);
        expect(reqExn.exn.d).toBe(csExnSaid);
        const corrId = reqExn.exn.d as string;
        const payload = reqExn.exn.a as { n: string; l: any[] };
        const cred = payload.l[0];
        console.log("[M1] received /wap/iss corrId=%s", corrId);

        let m1AckExn: any = null;
        let m1AckSigs: string[] = [];
        let m2AckSigs: string[] = [];

        await Promise.all([
            // ── M1: pre-compute VCP → ISS chain, send both exchanges upfront ────
            // Same OOR pattern as tests 1-5: M1 queues both events before waiting.
            // KERIA holds ISS in escrow until VCP commits, then cascades.
            (async () => {
                const regResult = await m1Client.registries().create({
                    name: "G1v2", registryName: `wap-reg-${nonce}`, nonce,
                });
                const vcpIxnSn = parseInt(regResult.serder.ked.s, 16);
                const vcpIxnSaid = regResult.serder.ked.d as string;
                console.log("[M1] VCP queued: ixnSn=%d (op NOT awaited)", vcpIxnSn);

                const issResult = await m1Client.credentials().issue("G1v2", {
                    i: g1Prefix, ri: regk,
                    s: cred.s, a: cred.a,
                    ...(cred.u ? { u: cred.u } : {}),
                }, { sn: vcpIxnSn, d: vcpIxnSaid });
                console.log("[M1] ISS queued: ixnSn=%d (op NOT awaited)", issResult.anc.sn);

                const issEmbed = await buildCredentialEmbed(m1Client, g1HabM1, issResult);
                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId },
                    buildRegistryEmbed(regResult), [m2Hab.prefix]
                );
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId },
                    issEmbed, [m2Hab.prefix]
                );
                console.log("[M1] VCP+ISS exchanges sent — waiting for ops");

                await Promise.all([
                    waitOperation(m1Client, await regResult.op()),
                    waitOperation(m1Client, issResult.op),
                ]);
                console.log("[M1] VCP+ISS ops done");

                const [ackExn, ackSigs] = await m1Client.exchanges().createExchangeMessage(
                    g1HabM1, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: reqExn.exn.d },
                    {}, reqExn.exn.i, reqExn.exn.dt, reqExn.exn.d
                );
                m1AckExn = ackExn;
                m1AckSigs = ackSigs;
                await m1Client.notifications().mark(m1Note.i);
            })(),

            // ── M2: poll for both exchanges, co-sign VCP first then ISS ─────────
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId], m2Hab.prefix, 2, 90000
                );
                const vcpExch = allExchanges.find((e: any) => e.exn.r === "/multisig/vcp")!;
                const issExch = allExchanges.find((e: any) => e.exn.r === "/multisig/iss")!;

                // Phase 1: co-sign VCP
                const vcpAncFull = vcpExch.exn.e?.anc as { s: string; p: string };
                const vcpTargetSn = parseInt(vcpAncFull.s, 16);
                const m2Reg = await m2Client.registries().create({
                    name: "G1v2", registryName: `wap-reg-${nonce}`, nonce,
                    anchorPoint: { sn: vcpTargetSn - 1, d: vcpAncFull.p },
                });
                await m2Client.exchanges().send(
                    "m2", "registry", m2Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId },
                    buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                );
                // M2's KERIA checks ri in Tevers when credentials().issue() is called — registry only exists there after VCP commits. M1 skips this.
                await waitOperation(m2Client, await m2Reg.op());
                console.log("[M2] VCP committed");

                // Phase 2: co-sign ISS
                const acdc = issExch.exn.e?.acdc as Record<string, unknown>;
                const iss = issExch.exn.e?.iss as { ri: string };
                const issAncFull = issExch.exn.e?.anc as { s: string; p: string };
                const issTargetSn = parseInt(issAncFull.s, 16);
                const m2Iss = await m2Client.credentials().issue("G1v2", {
                    i: g1Prefix, ri: iss.ri,
                    s: acdc.s as string, a: acdc.a as Record<string, unknown>,
                    ...(acdc.u ? { u: acdc.u as string } : {}),
                }, { sn: issTargetSn - 1, d: issAncFull.p });
                const m2IssEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                await m2Client.exchanges().send(
                    "m2", "multisig", m2Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId },
                    m2IssEmbed, [m1Hab.prefix]
                );
                await waitOperation(m2Client, m2Iss.op);
                console.log("[M2] ISS committed");

                const [, ackSigs2] = await m2Client.exchanges().createExchangeMessage(
                    g1HabM2, "/wap/iss/ack",
                    { r: "/wap/iss/ack", p: reqExn.exn.d },
                    {}, reqExn.exn.i, reqExn.exn.dt, reqExn.exn.d
                );
                m2AckSigs = ackSigs2;
            })(),
        ]);

        // Submit ACK with combined sigs from both members
        await m1Client.exchanges().sendFromEvents(
            "G1v2", "wap", m1AckExn, [...m1AckSigs, ...m2AckSigs], "", [csHab.prefix]
        );
        console.log("[M1] ACK submitted: said=%s", m1AckExn.ked.d);

        // CS receives ACK
        const [csAckNote] = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 1, 90000);
        expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
        await csClient.notifications().mark(csAckNote.i);
        console.log("[CS] received ACK: credential=%s", credSaid);

        // M1 fetches the committed credential (M1 is a G1 member so its KERIA has it)
        let m1Cred: any = null;
        for (let attempt = 0; attempt < 30 && !m1Cred?.anc; attempt++) {
            try { m1Cred = await m1Client.credentials().get(credSaid); } catch {}
            if (!m1Cred?.anc) await new Promise(r => setTimeout(r, 1000));
        }
        expect(m1Cred?.anc).toBeDefined();

        // G1 (M1+M2) grants the credential to holder via IPEX.
        // Both members sign the grant exn; anchor attachment is reused from issuance
        // so ipex().grant() doesn't re-sign the already-committed IXN.
        const grantDt = signifyDatetime();
        const grantArgs = {
            senderName: "G1v2",
            recipient: holderPrefix,
            acdc: new Serder(m1Cred.sad),
            iss: new Serder(m1Cred.iss),
            anc: new Serder(m1Cred.anc),
            acdcAttachment: m1Cred.atc,
            issAttachment: m1Cred.issatc,
            ancAttachment: m1Cred.ancatc,
            datetime: grantDt,
        };
        const [[grantExn, m1GrSigs, grantAtc], [, m2GrSigs]] = await Promise.all([
            m1Client.ipex().grant(grantArgs),
            m2Client.ipex().grant(grantArgs),
        ]);
        const grantOp = await m1Client.ipex().submitGrant(
            "G1v2", grantExn, [...m1GrSigs, ...m2GrSigs], grantAtc, [holderPrefix]
        );
        console.log("[G1] grant submitted: said=%s", grantExn.ked.d);

        // Holder admits back to G1
        const [holderGrantNote] = await waitForNotificationsCount(holderClient, "/exn/ipex/grant", 1, 90000);
        console.log("[HOLDER] received grant: exchSaid=%s", holderGrantNote.a.d);

        const admitDt = signifyDatetime();
        const [admit, aSigs, aEnd] = await holderClient.ipex().admit({
            senderName: "holder",
            message: "",
            grantSaid: holderGrantNote.a.d!,
            recipient: g1Prefix,
            datetime: admitDt,
        });
        const admitOp = await holderClient.ipex().submitAdmit("holder", admit, aSigs, aEnd, [g1Prefix]);
        await holderClient.notifications().mark(holderGrantNote.i);

        await Promise.all([
            waitOperation(m1Client, grantOp),
            waitOperation(holderClient, admitOp),
        ]);
        console.log("[HOLDER] admitted credential");

        // KERIA stores the credential asynchronously — it first waits for G1's key state
        // in Tevers (populated from witness queries). This can take up to ~60 seconds.
        let holderCred: any = null;
        for (let attempt = 0; attempt < 90 && !holderCred; attempt++) {
            await new Promise(r => setTimeout(r, 1000));
            const creds = await holderClient.credentials().list({ limit: 100 });
            holderCred = creds.find((c: any) => c.sad.d === credSaid);
        }
        expect(holderCred).toBeDefined();
        expect(holderCred.sad.i).toBe(g1Prefix);
        expect(holderCred.sad.a.i).toBe(holderPrefix);
        expect(holderCred.status.s).toBe("0");
        console.log("[HOLDER] credential verified: said=%s issuer=%s holder=%s",
            credSaid, g1Prefix, holderPrefix);
    }, 300000);
});
