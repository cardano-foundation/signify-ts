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
 * examples/.test-ooo3-chain.json to demonstrate offline pre-computation of sn+digest.
 *
 * Test 4 — multi-cred OOO (one registry per credential): flow1 issues 1 cred, flow2 issues 3 creds:
 * 8-event grouped chain — 4 VCPs (sn+1..sn+4) then 4 ISS (sn+5..sn+8). M1 pre-computes all 8
 * sn+digest values, writes them to examples/.test-ooo4-chain.json, then sends all VCPs in
 * descending sn order (sn+4→sn+3→sn+2→sn+1) and all ISS in descending sn order
 * (sn+8→sn+7→sn+6→sn+5). M2 co-signs in the same descending order per phase. KERIA holds
 * sn+2..sn+4 in psces until sn+1 commits then cascades all 3; same for the ISS group.
 * Demonstrates that KERIA can cascade a 4-deep escrow chain in both VCP and ISS phases.
 *
 * Test 5 — super-chaotic OOO: 1 shared registry per flow, VCPs and ISS fully interleaved:
 * 2 flows × 3 creds = 2 VCPs + 6 ISS = 8 ixn events. Only 2 registries (one per flow); all
 * credentials within a flow share that registry's ri. M1 pre-computes all 8 sn+digests, then
 * sends in a fully chaotic order where VCPs and ISS are interleaved:
 *   ISS_f2c2(sn+7) → VCP_f2(sn+2) → ISS_f1c3(sn+5) → ISS_f2c3(sn+8)
 *   → VCP_f1(sn+1) → ISS_f1c2(sn+4) → ISS_f2c1(sn+6) → ISS_f1c1(sn+3)
 * M2 filters VCPs out of the mixed exchange stream and co-signs them first (descending sn),
 * waits for the VCP cascade to commit both registries, then co-signs ISS in zigzag order
 * (alternating highest/lowest: sn+8→sn+3→sn+7→sn+4→sn+6→sn+5). The zigzag produces:
 * two immediate commits (sn+3, sn+4) then sn+5 triggers a 3-deep cascade (sn+6→sn+7→sn+8).
 * Chain state written to examples/.test-ooo5-chain.json.
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
import { spawnSync } from "child_process";

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

async function sendGroupAck(
    m1Client: SignifyClient,
    m2Client: SignifyClient,
    g1HabM1: any,
    g1HabM2: any,
    m1Hab: any,
    m2Hab: any,
    csPrefix: string,
    req: any
): Promise<void> {
    await Promise.all([
        (async () => {
            const [ackExn, ackSigs, ackAtc] = await m1Client.exchanges().createExchangeMessage(
                g1HabM1, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req.exn.d },
                {}, req.exn.i, req.exn.dt, req.exn.d
            );
            await m1Client.exchanges().sendFromEvents("G1v2", "wap", ackExn, ackSigs, ackAtc, [csPrefix]);
            const seal = ['SealEvent', { i: g1HabM1.prefix, s: g1HabM1['state']['ee']['s'], d: g1HabM1['state']['ee']['d'] }];
            const sigers = ackSigs.map((sig: string) => new Siger({ qb64: sig }));
            const wrapIms = d(messagize(ackExn, sigers, seal));
            const embAtc = wrapIms.substring(ackExn.size) + ackAtc;
            await m1Client.exchanges().send(
                "m1", "wap", m1Hab, "/multisig/exn",
                { gid: g1HabM1.prefix }, { exn: [ackExn, embAtc] }, [m2Hab.prefix]
            );
        })(),
        (async () => {
            const [ackExn, ackSigs, ackAtc] = await m2Client.exchanges().createExchangeMessage(
                g1HabM2, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req.exn.d },
                {}, req.exn.i, req.exn.dt, req.exn.d
            );
            await m2Client.exchanges().sendFromEvents("G1v2", "wap", ackExn, ackSigs, ackAtc, [csPrefix]);
            const seal = ['SealEvent', { i: g1HabM2.prefix, s: g1HabM2['state']['ee']['s'], d: g1HabM2['state']['ee']['d'] }];
            const sigers = ackSigs.map((sig: string) => new Siger({ qb64: sig }));
            const wrapIms = d(messagize(ackExn, sigers, seal));
            const embAtc = wrapIms.substring(ackExn.size) + ackAtc;
            await m2Client.exchanges().send(
                "m2", "wap", m2Hab, "/multisig/exn",
                { gid: g1HabM2.prefix }, { exn: [ackExn, embAtc] }, [m1Hab.prefix]
            );
        })(),
    ]);
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
                    client.exchanges().list({ filter: { "-r": route }, limit: 2000 }),
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

// The OOO scenarios in the first describe block are written for a 2-of-2
// group (m1 initiator + m2 sole cosigner). When the setup script created a
// larger group (e.g. N_MEMBERS=3 THRESHOLD=2), KERIA needs sigs from peers
// the OOO tests do not drive, so we skip them. The K-of-N describe block
// further down still runs for any group size.
const groupMembersCount = fs.existsSync(groupPath)
    ? (JSON.parse(fs.readFileSync(groupPath, "utf-8")).members?.length ?? 2)
    : 2;
const ooo2of2Describe = groupMembersCount === 2 ? describe : describe.skip;

ooo2of2Describe("WAP group issuance E2E (out-of-order, two concurrent flows)", () => {
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
    }, 10000);

    beforeEach(async () => {
        // Fresh clients per test — prevents accumulated KERIA exchange state from
        // one test's ops bleeding into another test's polls or notification reads.
        console.log("[SETUP] Connecting fresh clients...");
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

        // Mark leftover unread notes so prior test failures don't pollute this test.
        // CS routes /wap/iss to both M1 and M2 (both agent OOBIs resolved), so
        // M2 also accumulates /exn/wap/iss notifications that need clearing.
        // Holder can have leftover /exn/ipex/grant if test 6 failed mid-flow.
        const [m1NotesAll, m2NotesAll, csNotesAll, holderNotesAll] = await Promise.all([
            m1Client.notifications().list(0, 1000),
            m2Client.notifications().list(0, 1000),
            csClient.notifications().list(0, 1000),
            holderClient.notifications().list(0, 1000),
        ]);
        const leftoverM1 = (m1NotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/wap/iss" && n.r === false
        );
        const leftoverM2 = (m2NotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/wap/iss" && n.r === false
        );
        const leftoverCs = (csNotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/wap/iss/ack" && n.r === false
        );
        const leftoverHolder = (holderNotesAll.notes ?? []).filter(
            (n: any) => n.a.r === "/exn/ipex/grant" && n.r === false
        );
        await Promise.all([
            ...leftoverM1.map((n: any) => m1Client.notifications().mark(n.i)),
            ...leftoverM2.map((n: any) => m2Client.notifications().mark(n.i)),
            ...leftoverCs.map((n: any) => csClient.notifications().mark(n.i)),
            ...leftoverHolder.map((n: any) => holderClient.notifications().mark(n.i)),
        ]);
        if (leftoverM1.length || leftoverM2.length || leftoverCs.length || leftoverHolder.length) {
            console.log("[BEFORE EACH] Cleared %d M1 notes, %d M2 notes, %d CS notes, %d holder notes",
                leftoverM1.length, leftoverM2.length, leftoverCs.length, leftoverHolder.length);
        }
    }, 60000);

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
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOO Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOO Flow2",
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

            // ── M2: two flows concurrently, within each flow VCP→ISS using VCP IXN anchor ──
            // OOO: ISS IXN is submitted while VCP IXN may still be in psces — KERIA cascades.
            // VCP HTTP response is awaited to get the IXN said before ISS is submitted.
            // This is the same pattern M1 uses — no wait for VCP op between VCP and ISS.
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId1, corrId2], m2Hab.prefix, 4
                );

                console.log("[M2] got all 4 exchanges — co-signing 2 flows concurrently");

                const allOps = await Promise.all(
                    [corrId1, corrId2].map(async (corrId) => {
                        const nonce = corrId === corrId1 ? nonce1 : nonce2;
                        const vcpExch = allExchanges.find(
                            (e: any) => e.exn.r === "/multisig/vcp" && e.exn.a?.correlationId === corrId
                        )!;
                        const issExch = allExchanges.find(
                            (e: any) => e.exn.r === "/multisig/iss" && e.exn.a?.correlationId === corrId
                        )!;

                        // VCP co-sign — await HTTP response to get IXN sn+said for ISS anchor
                        const vcpAncFull = vcpExch.exn.e?.anc as { s: string; p: string };
                        const vcpTargetSn = parseInt(vcpAncFull.s, 16);
                        const m2Reg = await m2Client.registries().create({
                            name: "G1v2", registryName: `wap-registry-${nonce}`, nonce,
                            anchorPoint: { sn: vcpTargetSn - 1, d: vcpAncFull.p },
                        });
                        await m2Client.exchanges().send(
                            "m2", "registry", m2Hab, "/multisig/vcp",
                            { gid: g1Prefix, correlationId: corrId },
                            buildRegistryEmbed(m2Reg), [m1Hab.prefix]
                        );
                        const vcpIxnSn = parseInt(m2Reg.serder.ked.s, 16);
                        console.log("[M2] VCP co-sign sent (corrId=...%s), IXN sn=%d", corrId.slice(-6), vcpIxnSn);

                        // ISS co-sign — use M1's ISS IXN anchor from the embed.
                        // M1 built a grouped chain: VCP1(N+1)→VCP2(N+2)→ISS1(N+3)→ISS2(N+4).
                        // Using vcpIxnSn as anchor would place ISS at N+2, colliding with VCP2.
                        // Reading issExch.exn.e.anc gives the correct target sn (N+3 or N+4).
                        const issExn = issExch.exn.e as any;
                        const issAncFull = issExn.anc as { s: string; p: string };
                        const issTargetSn = parseInt(issAncFull.s, 16);
                        const m2Iss = await m2Client.credentials().issue("G1v2", {
                            i: g1Prefix,
                            ri: (issExn.iss as { ri: string }).ri,
                            s: (issExn.acdc as Record<string, unknown>).s as string,
                            a: (issExn.acdc as Record<string, unknown>).a as Record<string, unknown>,
                            ...((issExn.acdc as Record<string, unknown>).u
                                ? { u: (issExn.acdc as Record<string, unknown>).u as string }
                                : {}),
                        }, { sn: issTargetSn - 1, d: issAncFull.p });
                        const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2Iss);
                        await m2Client.exchanges().send(
                            "m2", "multisig", m2Hab, "/multisig/iss",
                            { gid: g1Prefix, correlationId: corrId },
                            issEmbed, [m1Hab.prefix]
                        );
                        console.log("[M2] ISS co-sign sent (corrId=...%s), IXN sn=%d — VCP2 may still be in psces", corrId.slice(-6), m2Iss.anc.sn);

                        return [m2Reg.op(), m2Iss.op];
                    })
                );

                console.log("[M2] all co-signs queued — waiting for KERIA escrow cascade");
                await Promise.all(allOps.flat().map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] all 4 ops done");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, req);
            console.log("[ACK] submitted corrId=...%s", req.exn.d.slice(-8));
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
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder ReverseOOO Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder ReverseOOO Flow2",
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

        console.log("[TEST] Explicit reverse OOO — grouped chain VCP1→VCP2→ISS1→ISS2, sent in reverse sn=4..1");

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

            // ── M2: co-sign all 4 in reversed order (VCP2→VCP1→ISS2→ISS1), no wait between ──
            // VCPs reversed: KERIA escrows VCP2 until VCP1 commits → cascade.
            // ISS reversed: KERIA escrows ISS2 until ISS1 commits → cascade.
            // credentialing.py:664 guard removed — ISS submitted before VCP commits, KERIA escrows.
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
                    "[M2] VCP order: %s — ISS order: %s",
                    vcpExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→"),
                    issExchanges.map((e: any) => parseInt(e.exn.e?.anc?.s ?? "0", 16)).join("→")
                );

                const allOps: Array<any> = [];

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
                    console.log("[M2] VCP co-sign queued: sn=%d", targetSn);
                    allOps.push(m2Reg.op());
                }

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
                    console.log("[M2] ISS co-sign queued: sn=%d", targetSn);
                    allOps.push(m2Iss.op);
                }

                await Promise.all(allOps.map(async (p) => waitOperation(m2Client, await p)));
                console.log("[M2] all 4 ops done — cascade completed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, req);
            console.log("[ACK] submitted corrId=...%s", req.exn.d.slice(-8));
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
            d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOO3 Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];
        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOO3 Flow2",
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
        const chainPath = path.join(__dirname, "../../examples/.test-ooo3-chain.json");
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

                // credentialing.py:664 guard removed — no wait needed before ISS

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
                    waitOperation(m2Client, await m2Reg2.op()),
                    waitOperation(m2Client, await m2Reg1.op()),
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
            await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, req);
            console.log("[ACK] submitted corrId=...%s", req.exn.d.slice(-8));
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

    it("multi-cred OOO: flow1 issues 1 cred, flow2 issues 3 creds — M1 pre-computes 8-event chain, sends all VCPs reversed then all ISS reversed — KERIA cascades both groups of 4", async () => {
        const [nonce1, nonce2, nonce3, nonce4] = [randomNonce(), randomNonce(), randomNonce(), randomNonce()];
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);
        const regk3 = computeRegk(g1Prefix, nonce3);
        const regk4 = computeRegk(g1Prefix, nonce4);

        // ── CS builds ACDCs: flow1 has 1 cred, flow2 has 3 creds ─────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({ d: "", i: holderPrefix, dt: dt1, attendeeName: "Holder OOO4 Flow1 Cred1" })[1];
        const acdcSad1 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1, s: SCHEMA_SAID, a: aBlock1 })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({ d: "", i: holderPrefix, dt: dt2, attendeeName: "Holder OOO4 Flow2 Cred1" })[1];
        const acdcSad2 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2, s: SCHEMA_SAID, a: aBlock2 })[1];

        const dt3 = signifyDatetime();
        const aBlock3 = Saider.saidify({ d: "", i: holderPrefix, dt: dt3, attendeeName: "Holder OOO4 Flow2 Cred2" })[1];
        const acdcSad3 = Saider.saidify({ v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk3, s: SCHEMA_SAID, a: aBlock3 })[1];

        const dt4 = signifyDatetime();
        const aBlock4 = Saider.saidify({ d: "", i: holderPrefix, dt: dt4, attendeeName: "Holder OOO4 Flow2 Cred3" })[1];
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
        const chainPath = path.join(__dirname, "../../examples/.test-ooo4-chain.json");
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

                // credentialing.py:664 guard removed — ISS submitted without waiting for VCP ops

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

                await Promise.all([
                    ...vcpOpPromises.map(async (p) => waitOperation(m2Client, await p)),
                    ...issOpPromises.map((op) => waitOperation(m2Client, op)),
                ]);
                console.log("[M2] all 8 ops done");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, req);
            console.log("[ACK] submitted corrId=...%s", req.exn.d.slice(-8));
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

    it("super-chaotic OOO: 1 shared registry per flow, M1 interleaves VCPs and ISS freely — M2 zigzag ISS order triggers 3-deep cascade at sn+5", async () => {
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
        const acdcSad_f1c1 = makeAcdc(regk1, "Holder OOO5 Flow1 Cred1");
        const acdcSad_f1c2 = makeAcdc(regk1, "Holder OOO5 Flow1 Cred2");
        const acdcSad_f1c3 = makeAcdc(regk1, "Holder OOO5 Flow1 Cred3");
        const acdcSad_f2c1 = makeAcdc(regk2, "Holder OOO5 Flow2 Cred1");
        const acdcSad_f2c2 = makeAcdc(regk2, "Holder OOO5 Flow2 Cred2");
        const acdcSad_f2c3 = makeAcdc(regk2, "Holder OOO5 Flow2 Cred3");

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
        const chainPath = path.join(__dirname, "../../examples/.test-ooo5-chain.json");
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

                // credentialing.py:664 guard removed — ISS submitted without waiting for VCP ops

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

                await Promise.all([
                    ...vcpOpPromises.map(async (p) => waitOperation(m2Client, await p)),
                    ...issOpPromises.map((op) => waitOperation(m2Client, op)),
                ]);
                console.log("[M2] all 8 ops done");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows ─────────────────────────────────────────────────────
        for (const [req, note] of [[req1, note1], [req2, note2]] as [any, any][]) {
            await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, req);
            console.log("[ACK] submitted corrId=...%s", req.exn.d.slice(-8));
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
                .catch(() => { }),
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

        await Promise.all([
            // ── M1: pre-compute VCP → ISS chain, send both exchanges upfront ────
            // Same OOO pattern as tests 1-5: M1 queues both events before waiting.
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
                await m1Client.notifications().mark(m1Note.i);
            })(),

            // ── M2: poll for both exchanges, co-sign VCP+ISS without waiting between ─
            // guard in credentialing.py:664 commented out — testing if KERIA can escrow
            // the ISS internally until VCP commits (same as M1's pattern)
            (async () => {
                const allExchanges = await pollAllIncomingExchanges(
                    m2Client, [corrId], m2Hab.prefix, 2, 90000
                );
                const vcpExch = allExchanges.find((e: any) => e.exn.r === "/multisig/vcp")!;
                const issExch = allExchanges.find((e: any) => e.exn.r === "/multisig/iss")!;

                // co-sign VCP (op NOT awaited)
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
                console.log("[M2] VCP co-sign queued (op NOT awaited)");

                // co-sign ISS immediately (no wait for VCP op)
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
                console.log("[M2] ISS co-sign queued");

                await Promise.all([
                    waitOperation(m2Client, await m2Reg.op()),
                    waitOperation(m2Client, m2Iss.op),
                ]);
                console.log("[M2] VCP+ISS ops done");
            })(),
        ]);

        await sendGroupAck(m1Client, m2Client, g1HabM1, g1HabM2, m1Hab, m2Hab, csHab.prefix, reqExn);
        console.log("[ACK] submitted");

        // CS receives ACK
        const [csAckNote] = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 1, 90000);
        expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
        await csClient.notifications().mark(csAckNote.i);
        console.log("[CS] received ACK: credential=%s", credSaid);

        // M1 fetches the committed credential (M1 is a G1 member so its KERIA has it)
        let m1Cred: any = null;
        for (let attempt = 0; attempt < 30 && !m1Cred?.anc; attempt++) {
            try { m1Cred = await m1Client.credentials().get(credSaid); } catch { }
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
        // in Tevers (populated from witness queries). On fresh KERIA this can exceed 60 seconds.
        let holderCred: any = null;
        for (let attempt = 0; attempt < 180 && !holderCred; attempt++) {
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

    // Demonstrates anchoring multiple credential ISS events in a SINGLE ixn with
    // multiple seals (atomic, no chaining between credentials). KERI allows it at the
    // KEL level via interact(name, [seal1, seal2, ...]). The test commits one ixn
    // that anchors N ISS events at the same sn, then reads it back from the KEL
    // and asserts the data array carries all seals.
    //
    // Out of scope: the standard /identifiers/{name}/credentials KERIA endpoint takes
    // one acdc+iss+ixn per call, so registering all credentials with a shared ixn
    // would need a batch endpoint on KERIA. This test only proves the KEL primitive.
    it("multi-seal ixn: ten ISS events anchored atomically in one ixn", async () => {
        const CRED_COUNT = 10;
        const nonce = randomNonce();
        const issuerName = "m1";
        const issuerPrefix = m1Hab.prefix;
        const regk = computeRegk(issuerPrefix, nonce);

        // Create a fresh registry on M1's single-sig hab so we have a valid ri for the ISS events
        const regResult = await m1Client.registries().create({
            name: issuerName, registryName: `wap-multi-seal-${nonce}`, nonce,
        });
        await waitOperation(m1Client, await regResult.op());
        console.log("[MULTI-SEAL] registry created: regk=%s", regk);

        // Build N ACDCs + N ISS SADs (mirroring signify's saidify in credentials.issue)
        const buildIss = (attendeeName: string) => {
            const dt = signifyDatetime();
            const [, aBlock] = Saider.saidify({ d: "", i: holderHab.prefix, dt, attendeeName });
            const [, acdc] = Saider.saidify({
                v: versify(Ident.ACDC, undefined, Serials.JSON, 0),
                d: "", i: issuerPrefix, ri: regk, s: SCHEMA_SAID, a: aBlock,
            });
            const [, iss] = Saider.saidify({
                v: versify(Ident.KERI, undefined, Serials.JSON, 0),
                t: Ilks.iss, d: "", i: acdc.d, s: "0", ri: regk, dt: aBlock.dt,
            });
            return { acdc, iss };
        };
        const creds = Array.from({ length: CRED_COUNT }, (_, idx) =>
            buildIss(`Multi-seal ${idx + 1}`)
        );

        // Compose ONE ixn carrying N seals, one per ISS event. interact()'s data param
        // accepts an array — signify just forwards it as the ixn's `a` field
        const seals = creds.map((c) => ({ i: c.iss.i, s: c.iss.s, d: c.iss.d }));
        const ixnResult = await m1Client.identifiers().interact(issuerName, seals);
        await waitOperation(m1Client, await ixnResult.op());
        console.log("[MULTI-SEAL] ixn submitted: sn=%s d=%s seals=%d",
            ixnResult.serder.ked.s, ixnResult.serder.ked.d,
            ixnResult.serder.ked.a.length);

        // The ixn we just sent carries all seals in its `a` field, in input order
        expect(ixnResult.serder.ked.a).toHaveLength(CRED_COUNT);
        creds.forEach((c, idx) => {
            expect(ixnResult.serder.ked.a[idx].d).toBe(c.iss.d);
        });

        // KERIA committed the ixn to M1's KEL — fetching the hab back exposes its sn advanced
        const habAfter = await m1Client.identifiers().get(issuerName);
        const habSnAfter = parseInt(habAfter.state.s, 16);
        const ixnSn = parseInt(ixnResult.serder.ked.s, 16);
        expect(habSnAfter).toBeGreaterThanOrEqual(ixnSn);
        console.log("[MULTI-SEAL] hab sn after commit=%d (ixn sn=%d, %d seals)",
            habSnAfter, ixnSn, CRED_COUNT);
    }, 60000);

});

// ─────────────────────────────────────────────────────────────────────────────
// K-of-N IPEX grant/admit
//
// Replays the test 6 (2-of-2) IPEX grant/admit flow against an arbitrary
// group size loaded from .test-group.json. Verifies that:
//   - all N members receive /wap/iss (dual-OOBI / N-OOBI routing)
//   - cosigner fan-out: every cosigner broadcasts its /multisig/vcp and
//     /multisig/iss to every other member, KERIA accumulates sigs until the
//     stored threshold is met
//   - ACK: every member submits a partial /wap/iss/ack and broadcasts the
//     /multisig/exn wrapper; WapackSender delivers a single ACK to CS once
//     the threshold is reached
//   - grant: every member builds the grant locally with the same grantDt
//     (deterministic SAID); leader combines all sigs and submits
//   - holder admit + TEL fetch via any member-agent endpoint (NB registry)
//
// Setup:
//   docker-compose down -v && docker-compose up -d
//   N_MEMBERS=3 THRESHOLD=3 npx tsx examples/integration-scripts/utils/setup-all.ts  # 3-of-3
//   N_MEMBERS=3 THRESHOLD=2 npx tsx examples/integration-scripts/utils/setup-all.ts  # 2-of-3
// ─────────────────────────────────────────────────────────────────────────────

const groupSetupAvailable = fs.existsSync(groupPath) && fs.existsSync(clientsPath);
const kOfNDescribe = groupSetupAvailable ? describe : describe.skip;

interface MemberCtx {
    name: string;            // m1, m2, ..., mN
    client: SignifyClient;
    hab: any;                // member's own hab
    groupHab: any;           // group hab from this member's perspective
}

async function pollIncomingByRoute(
    client: SignifyClient,
    route: string,
    corrId: string,
    excludeSender: string,
    timeoutMs = 90000
): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const raw = (await client
            .exchanges()
            .list({ filter: { "-r": route }, limit: 2000 })) ?? [];
        const match = raw.find(
            (x: any) =>
                x.exn.a?.correlationId === corrId && x.exn.i !== excludeSender
        );
        if (match) return match;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`Timeout polling incoming ${route} for corrId=${corrId}`);
}

kOfNDescribe("WAP group issuance E2E — K-of-N IPEX grant/admit", () => {
    const env = resolveEnvironment();
    const groupData = groupSetupAvailable
        ? JSON.parse(fs.readFileSync(groupPath, "utf-8"))
        : { members: [], threshold: 0, name: "G1v2", prefix: "" };
    const memberNames: string[] = groupData.members.map((m: any) => m.name);
    const threshold: number = groupData.threshold ?? memberNames.length;
    const groupName = groupData.name as string;
    const g1Prefix = groupData.prefix as string;

    let memberClients: SignifyClient[] = [];
    let csClient: SignifyClient;
    let holderClient: SignifyClient;
    let csHab: any;
    let holderHab: any;
    let members: MemberCtx[] = [];

    beforeAll(async () => {
        if (!groupSetupAvailable) return;
        console.log(
            `[SETUP] ${threshold}-of-${memberNames.length} group ${groupName} prefix=${g1Prefix}`
        );
        void env;

        memberClients = await Promise.all(memberNames.map((n) => getClientFromFile(n)));
        [csClient, holderClient] = await Promise.all([
            getClientFromFile("cs"),
            getClientFromFile("holder"),
        ]);
        [csHab, holderHab] = await Promise.all([
            csClient.identifiers().get("cs"),
            holderClient.identifiers().get("holder"),
        ]);

        members = await Promise.all(
            memberClients.map(async (client, idx) => {
                const name = memberNames[idx];
                const hab = await client.identifiers().get(name);
                const groupHab = await client.identifiers().get(groupName);
                return { name, client, hab, groupHab };
            })
        );
    }, 60000);

    it(`${groupData.threshold ?? memberNames.length}-of-${memberNames.length}: G1 grants issued credential to holder`, async () => {
        const nonce = randomNonce();
        const regk = computeRegk(g1Prefix, nonce);
        const holderPrefix = holderHab.prefix;

        // Clear stale notifications from any prior run.
        const allClients = [...memberClients, csClient, holderClient];
        for (const c of allClients) {
            const notes = (await c.notifications().list(0, 1000)).notes ?? [];
            for (const n of notes) {
                if (n.r === false) await c.notifications().mark(n.i).catch(() => { });
            }
        }

        // CS builds the ACDC and sends /wap/iss to the group prefix. Because CS
        // resolved G1 via every member-agent endpoint, KERIA's StreamPoster
        // delivers the exchange to all N members.
        const credDt = signifyDatetime();
        const aBlock = Saider.saidify({
            d: "",
            i: holderPrefix,
            dt: credDt,
            attendeeName: `Holder ${threshold}-of-${memberNames.length}`,
        })[1];
        const acdcSad = Saider.saidify({
            v: "ACDC10JSON000000_",
            d: "",
            i: g1Prefix,
            ri: regk,
            s: SCHEMA_SAID,
            a: aBlock,
        })[1];
        const credSaid = acdcSad.d as string;

        const wapDt = signifyDatetime();
        const [csExn, csSigs, csAtc] = await csClient
            .exchanges()
            .createExchangeMessage(
                csHab,
                "/wap/iss",
                { n: nonce, l: [acdcSad] },
                {},
                g1Prefix,
                wapDt
            );
        const csExnSaid = csExn.ked.d as string;
        await csClient
            .exchanges()
            .sendFromEvents("cs", "iss", csExn, csSigs, csAtc, [g1Prefix]);
        console.log(`[CS] sent /wap/iss said=${csExnSaid} cred=${credSaid}`);

        // Every member receives /wap/iss.
        const memberWapNotes = await Promise.all(
            members.map((m) =>
                waitForNotificationsCount(m.client, "/exn/wap/iss", 1, 30000).then(
                    (notes) => notes[0]
                )
            )
        );
        const leaderNote = memberWapNotes[0];
        const reqExn = await members[0].client.exchanges().get(leaderNote.a.d!);
        expect(reqExn.exn.d).toBe(csExnSaid);
        const corrId = reqExn.exn.d as string;
        const cred = (reqExn.exn.a as any).l[0];
        console.log(`[ALL] received /wap/iss corrId=${corrId}`);

        const leader = members[0];
        const cosigners = members.slice(1);
        const otherAids = (self: MemberCtx) =>
            members.filter((m) => m.hab.prefix !== self.hab.prefix).map((m) => m.hab.prefix);

        // Leader creates VCP+ISS and fans them out to every cosigner.
        const regResult = await leader.client.registries().create({
            name: groupName,
            registryName: `wap-reg-${nonce}`,
            nonce,
        });
        const vcpIxnSn = parseInt(regResult.serder.ked.s, 16);
        const vcpIxnSaid = regResult.serder.ked.d as string;
        const issResult = await leader.client.credentials().issue(
            groupName,
            {
                i: g1Prefix,
                ri: regk,
                s: cred.s,
                a: cred.a,
                ...(cred.u ? { u: cred.u } : {}),
            },
            { sn: vcpIxnSn, d: vcpIxnSaid }
        );
        const issEmbed = await buildCredentialEmbed(leader.client, leader.groupHab, issResult);

        await leader.client.exchanges().send(
            leader.name,
            "registry",
            leader.hab,
            "/multisig/vcp",
            { gid: g1Prefix, correlationId: corrId },
            buildRegistryEmbed(regResult),
            otherAids(leader)
        );
        await leader.client.exchanges().send(
            leader.name,
            "multisig",
            leader.hab,
            "/multisig/iss",
            { gid: g1Prefix, correlationId: corrId },
            issEmbed,
            otherAids(leader)
        );
        console.log(`[${leader.name}] broadcast VCP+ISS to ${cosigners.length} peer(s)`);

        // Every cosigner mirrors VCP+ISS locally and broadcasts to all other
        // members. KERIA accumulates server-side until threshold sigs land.
        const cosignerFlows = cosigners.map((co) =>
            (async () => {
                const vcpExch = await pollIncomingByRoute(
                    co.client,
                    "/multisig/vcp",
                    corrId,
                    co.hab.prefix
                );
                const vcpAnc = vcpExch.exn.e?.anc as { s: string; p: string };
                const vcpTargetSn = parseInt(vcpAnc.s, 16);
                const coReg = await co.client.registries().create({
                    name: groupName,
                    registryName: `wap-reg-${nonce}`,
                    nonce,
                    anchorPoint: { sn: vcpTargetSn - 1, d: vcpAnc.p },
                });
                await co.client.exchanges().send(
                    co.name,
                    "registry",
                    co.hab,
                    "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId },
                    buildRegistryEmbed(coReg),
                    otherAids(co)
                );

                const issExch = await pollIncomingByRoute(
                    co.client,
                    "/multisig/iss",
                    corrId,
                    co.hab.prefix
                );
                const issAcdc = issExch.exn.e?.acdc as Record<string, unknown>;
                const issIss = issExch.exn.e?.iss as { ri: string };
                const issAnc = issExch.exn.e?.anc as { s: string; p: string };
                const issTargetSn = parseInt(issAnc.s, 16);
                const coIss = await co.client.credentials().issue(
                    groupName,
                    {
                        i: g1Prefix,
                        ri: issIss.ri,
                        s: issAcdc.s as string,
                        a: issAcdc.a as Record<string, unknown>,
                        ...(issAcdc.u ? { u: issAcdc.u as string } : {}),
                    },
                    { sn: issTargetSn - 1, d: issAnc.p }
                );
                const coIssEmbed = await buildCredentialEmbed(co.client, co.groupHab, coIss);
                await co.client.exchanges().send(
                    co.name,
                    "multisig",
                    co.hab,
                    "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId },
                    coIssEmbed,
                    otherAids(co)
                );

                await Promise.all([
                    waitOperation(co.client, await coReg.op()),
                    waitOperation(co.client, coIss.op),
                ]);
                console.log(`[${co.name}] VCP+ISS cofirms committed`);
            })()
        );

        await Promise.all([
            Promise.all([
                waitOperation(leader.client, await regResult.op()),
                waitOperation(leader.client, issResult.op),
            ]).then(() => console.log(`[${leader.name}] VCP+ISS committed`)),
            ...cosignerFlows,
        ]);

        // Every member submits its partial ACK and broadcasts the wrapper.
        // WapackSender accumulates server-side; CS receives exactly one ACK
        // once `threshold` sigs land.
        await Promise.all(
            members.map((m) =>
                (async () => {
                    const note = memberWapNotes[members.indexOf(m)];
                    const myReq = await m.client.exchanges().get(note.a.d!);
                    const [ackExn, ackSigs, ackAtc] = await m.client
                        .exchanges()
                        .createExchangeMessage(
                            m.groupHab,
                            "/wap/iss/ack",
                            { r: "/wap/iss/ack", p: myReq.exn.d },
                            {},
                            myReq.exn.i,
                            myReq.exn.dt,
                            myReq.exn.d
                        );
                    await m.client
                        .exchanges()
                        .sendFromEvents(groupName, "wap", ackExn, ackSigs, ackAtc, [
                            csHab.prefix,
                        ]);
                    const seal = [
                        "SealEvent",
                        {
                            i: m.groupHab.prefix,
                            s: m.groupHab["state"]["ee"]["s"],
                            d: m.groupHab["state"]["ee"]["d"],
                        },
                    ];
                    const sigers = ackSigs.map(
                        (sig: string) => new Siger({ qb64: sig })
                    );
                    const wrapIms = d(messagize(ackExn, sigers, seal));
                    const embAtc = wrapIms.substring(ackExn.size) + ackAtc;
                    await m.client.exchanges().send(
                        m.name,
                        "wap",
                        m.hab,
                        "/multisig/exn",
                        { gid: m.groupHab.prefix },
                        { exn: [ackExn, embAtc] },
                        otherAids(m)
                    );
                    await m.client.notifications().mark(note.i);
                })()
            )
        );
        console.log("[ALL] ACK submitted + wrappers broadcast");

        const csAckNotes = await waitForNotificationsCount(
            csClient,
            "/exn/wap/iss/ack",
            1,
            120000
        );
        expect(csAckNotes[0].a.r).toBe("/exn/wap/iss/ack");
        for (const n of csAckNotes) {
            await csClient.notifications().mark(n.i);
        }
        console.log(`[CS] received ACK for credential=${credSaid}`);

        // Leader fetches the committed credential.
        let leaderCred: any = null;
        for (let attempt = 0; attempt < 60 && !leaderCred?.anc; attempt++) {
            try {
                leaderCred = await leader.client.credentials().get(credSaid);
            } catch {
                /* not yet */
            }
            if (!leaderCred?.anc) {
                await new Promise((r) => setTimeout(r, 1000));
            }
        }
        expect(leaderCred?.anc).toBeDefined();

        // Every member builds the grant locally against shared args (same dt
        // makes the SAID deterministic). For K-of-N with K<N the surplus sigs
        // are harmless; KERIA validates by sig index.
        const grantDt = signifyDatetime();
        const grantArgs = {
            senderName: groupName,
            recipient: holderPrefix,
            acdc: new Serder(leaderCred.sad),
            iss: new Serder(leaderCred.iss),
            anc: new Serder(leaderCred.anc),
            acdcAttachment: leaderCred.atc,
            issAttachment: leaderCred.issatc,
            ancAttachment: leaderCred.ancatc,
            datetime: grantDt,
        };
        const grantResults = await Promise.all(
            members.map((m) => m.client.ipex().grant(grantArgs))
        );
        const grantExn = grantResults[0][0];
        const combinedSigs: string[] = [];
        for (const [, sigs] of grantResults) {
            combinedSigs.push(...sigs);
        }
        const grantAtc = grantResults[0][2];

        const grantOp = await leader.client
            .ipex()
            .submitGrant(groupName, grantExn, combinedSigs, grantAtc, [holderPrefix]);
        console.log(`[${leader.name}] grant submitted said=${grantExn.ked.d}`);

        // Holder admits.
        const [holderGrantNote] = await waitForNotificationsCount(
            holderClient,
            "/exn/ipex/grant",
            1,
            90000
        );
        const admitDt = signifyDatetime();
        const [admit, aSigs, aEnd] = await holderClient.ipex().admit({
            senderName: "holder",
            message: "",
            grantSaid: holderGrantNote.a.d!,
            recipient: g1Prefix,
            datetime: admitDt,
        });
        const admitOp = await holderClient
            .ipex()
            .submitAdmit("holder", admit, aSigs, aEnd, [g1Prefix]);
        await holderClient.notifications().mark(holderGrantNote.i);

        await Promise.all([
            waitOperation(leader.client, grantOp),
            waitOperation(holderClient, admitOp),
        ]);

        // The holder's KERIA pulls the TEL via witq.telquery from any of the
        // member agent endpoints (resolved via the N-OOBI setup). NB registries
        // never publish TEL events to witnesses, so this is the only path that
        // makes the credential land.
        let holderCred: any = null;
        for (let attempt = 0; attempt < 180 && !holderCred; attempt++) {
            await new Promise((r) => setTimeout(r, 1000));
            const creds = await holderClient.credentials().list({ limit: 100 });
            holderCred = creds.find((c: any) => c.sad.d === credSaid);
        }
        expect(holderCred).toBeDefined();
        expect(holderCred.sad.i).toBe(g1Prefix);
        expect(holderCred.sad.a.i).toBe(holderPrefix);
        expect(holderCred.status.s).toBe("0");
        console.log(
            `[HOLDER] verified credential said=${credSaid} issuer=${g1Prefix}`
        );
    }, 600000);
});

// ═══════════════════════════════════════════════════════════════════════════
//                          KERIA BUG REPRO
//
// Wallet flow being mirrored:
//   1. CS sends /wap/iss to group G1. Both members receive the notification.
//   2. M1 user accepts FIRST. Wallet's initiator path:
//        - registries.create (own VCP partial)
//        - credentials.issue (own ISS partial)
//        - send /multisig/vcp to M2  ← M1's VCP partial enters KERIA escrow
//        - send /multisig/iss to M2  ← M1's ISS partial enters KERIA escrow
//        - await Promise.all([VCP op, ISS op])  ← BLOCKS until M2 cosigns
//        - sendGroupAck → partial-sig /wap/iss/ack to KERIA + /multisig/exn
//          wrapper to M2.
//   3. M2 user accepts second. Wallet's cosigner path (`drainQueuedIssCosign`
//      starts ACK before ISS cosign — the "early-ACK" mitigation):
//        - registries.create (cosign VCP)
//        - send /multisig/vcp to M1
//        - await VCP op  ← KERIA combines M1+M2 VCP partials, commits
//        - sendGroupAck → partial-sig /wap/iss/ack to KERIA + /multisig/exn
//        - credentials.issue (cosign ISS)
//        - send /multisig/iss to M1  ← KERIA combines ISS, ISS op resolves
//          on M1 side, M1's Promise.all returns
//   4. The two ACK partials hit KERIA seconds apart (M2 first because of
//      early-ACK; M1 second after VCP+ISS combine). KERIA does NOT merge
//      them. KERIA log shows:
//        - 100+ recurring `Exchange partially signed failed: Not enough
//          signatures in [1]` for the ACK SAID (M2's partial alone)
//        - only 2 transient `Not enough signatures in [0]` for the same
//          SAID (M1's partial — parsed twice on arrival, then silently
//          dropped, never enters the recurring escrow)
//      Threshold never reached → CS never gets /exn/wap/iss/ack. KERIA
//      pegs CPU at 100% indefinitely; state persists to LMDB and survives
//      `docker compose restart keria` (only `docker volume rm` clears it).
//
// Why the other tests in this file do NOT expose it:
//   They submit M1+M2 partials via `Promise.all` — both partials hit KERIA
//   microseconds apart and the merge path runs synchronously. The wallet
//   cannot Promise.all across two devices, so the second partial always
//   arrives after the first has entered the spin loop.
//
// Suggested KERIA-side fixes?
//   (a) On arrival of a new partial for a SAID that is already in
//       partial-sig escrow, MERGE the sig into the existing entry instead
//       of dropping or creating a new bucket. This is the root cause.
//   (b) Add backoff inside `processEscrowPartialSigned` so the re-verify
//       loop does not peg CPU when threshold is unmet. Mitigates the
//       failure mode but does not fix the root cause.
//   (c) Persist epse/epsd/esigs across restarts AND clear stuck escrows
//       on startup instead of resuming the spin.
//
// How to run (must be on a clean KERIA — the bug persists state to LMDB
// so a stale spin from a prior run will skew the counts):
//
//   cd PRIVATE-veridian-wallet
//   docker-compose down -v && docker-compose up -d
//   sleep 10
//   npm run test:wap-e2e:setup
//   cd signify-ts
//   TEST_ENVIRONMENT=local npx jest \
//       examples/integration-scripts/wap-group-issuance-ooo.test.ts \
//       -t "wallet flow exact replay" --testTimeout=300000 --verbose
//
// Inspect KERIA logs for the bug pattern:
//
//   docker logs private-veridian-wallet-keria-1 \
//       | grep -E "Missing escrowed anchor|not in Tevers|Exchange partially signed"
//
// Expected counts on a successful repro (clean KERIA, 10s tap delay):
//
//   Tevery unescrow failed:              ~1500–3000
//   Tevery unescrow error:               ~700–1500
//   Verifier unescrow failed:            ~400–1000
//   Exchange partially signed failed [1]: ~400–700
//
// The test prints these counts at the end and asserts the cascade fired.
// ═══════════════════════════════════════════════════════════════════════════

const keriaBugReprosDescribe = fs.existsSync(clientsPath) && fs.existsSync(groupPath)
    ? describe
    : describe.skip;

keriaBugReprosDescribe("WAP group issuance E2E — KERIA bug repros", () => {
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
        if (!fs.existsSync(clientsPath) || !fs.existsSync(groupPath)) {
            throw new Error(
                `Clients/group file missing. Run setup first:\n  npm run test:wap-e2e:setup`
            );
        }
        void env;
    }, 10000);

    beforeEach(async () => {
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

        // Drain leftover unread /exn/wap/iss + /exn/wap/iss/ack notifications
        // from prior test runs so each repro starts on a clean state. Uses a
        // smaller page size so a long backlog (e.g. after a manual wallet run)
        // does not blow the beforeEach timeout.
        const PAGE = 100;
        const drain = async (
            client: SignifyClient,
            match: (n: any) => boolean
        ): Promise<void> => {
            let start = 0;
            for (let i = 0; i < 10; i++) {
                const res = await client.notifications().list(start, start + PAGE - 1);
                const notes = res.notes ?? [];
                if (notes.length === 0) break;
                const unread = notes.filter((n: any) => n.r === false && match(n));
                await Promise.all(unread.map((n: any) => client.notifications().mark(n.i)));
                if (notes.length < PAGE) break;
                start += PAGE;
            }
        };
        await Promise.all([
            drain(m1Client, (n) => n.a.r === "/exn/wap/iss"),
            drain(m2Client, (n) => n.a.r === "/exn/wap/iss"),
            drain(csClient, (n) => n.a.r === "/exn/wap/iss/ack"),
            drain(holderClient, (n) => n.a.r === "/exn/ipex/grant"),
        ]);
    }, 180000);

    it("KERIA bug repro: wallet flow exact replay — M2 early-ACK between VCP and ISS cosign, M1 ACK after Promise.all unblocks. CS never receives /exn/wap/iss/ack", async () => {
        // ── Setup ──────────────────────────────────────────────────────────
        const nonce = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const holderPrefix = holderHab.prefix;
        const regk = computeRegk(g1Prefix, nonce);

        const [holderCs, holderG1] = await Promise.all([
            holderClient.contacts().get(csHab.prefix).catch(() => null),
            holderClient.contacts().get(g1Prefix).catch(() => null),
        ]);
        const m1OobiStr = (await m1Client.oobis().get("m1", "agent")).oobis[0] as string;
        const keriaBase = m1OobiStr.replace(/http:\/\/keria:/g, "http://127.0.0.1:").split("/oobi/")[0];
        const credServerBase = env.preset === "local" ? "http://localhost:3001" : "http://cred-issuance:3001";
        const schemaOobi = `${credServerBase}/oobi/${SCHEMA_SAID}`;
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
                .catch(() => { }),
        ]);

        // ── Continuous notification polling on all 4 agents (the wallet's
        //    KeriaNotificationService is always polling — KERIA is never idle).
        let polling = true;
        const POLL_INTERVAL_MS = 200;
        const pollStats = { m1: 0, m2: 0, cs: 0, holder: 0 };
        const pollLoop = async (client: SignifyClient, label: keyof typeof pollStats) => {
            while (polling) {
                try { await client.notifications().list(0, 50); pollStats[label]++; }
                catch (e) { /* ignore transient */ }
                await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
            }
        };
        const pollPromises = [
            pollLoop(m1Client, "m1"),
            pollLoop(m2Client, "m2"),
            pollLoop(csClient, "cs"),
            pollLoop(holderClient, "holder"),
        ];

        try {
            // ── CS builds the credential template and sends /wap/iss to G1 ──────
            const credDt = signifyDatetime();
            const aBlock = Saider.saidify({
                d: "", i: holderPrefix, dt: credDt, attendeeName: "Wallet Replay",
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
            console.log("[REPLAY] CS sent /wap/iss said=%s cred=%s", csExnSaid, credSaid);

            // Both members observe the request
            const [m1Note] = await waitForNotificationsCount(m1Client, "/exn/wap/iss", 1, 30000);
            const [m2Note] = await waitForNotificationsCount(m2Client, "/exn/wap/iss", 1, 30000);
            const reqExn = await m1Client.exchanges().get(m1Note.a.d!);
            expect(reqExn.exn.d).toBe(csExnSaid);
            const corrId = reqExn.exn.d as string;
            const payload = reqExn.exn.a as { n: string; l: any[] };
            const cred = payload.l[0];
            console.log("[REPLAY] both members received /wap/iss corrId=%s", corrId);

            const ackPayload = { r: "/wap/iss/ack", p: reqExn.exn.d };

            // ── Parallel two-member flow exactly matching the wallet ────────────
            // M1 is the initiator: queues VCP+ISS, broadcasts, then BLOCKS on
            //   await Promise.all([VCP op, ISS op]) until M2 has cosigned both.
            //   Once unblocked, M1 sends its /wap/iss/ack partial.
            // M2 is the cosigner: receives /multisig/vcp+iss, cosigns VCP and
            //   waits for the VCP op, then sends its /wap/iss/ack partial
            //   (early-ACK), then cosigns ISS and sends /multisig/iss. M2's ISS
            //   send is what unblocks M1's await.
            let m2AckSentAt = 0;
            let m1AckSentAt = 0;
            let m1AckSaid = "";

            const tFlowStart = Date.now();
            await Promise.all([
                // ────────────── M1 initiator path ──────────────
                (async () => {
                    const m1RegResult = await m1Client.registries().create({
                        name: "G1v2", registryName: `wap-reg-${nonce}`, nonce,
                    });
                    const m1VcpIxnSn = parseInt(m1RegResult.serder.ked.s, 16);
                    const m1VcpIxnSaid = m1RegResult.serder.ked.d as string;

                    const m1IssResult = await m1Client.credentials().issue("G1v2", {
                        i: g1Prefix, ri: regk,
                        s: cred.s, a: cred.a,
                        ...(cred.u ? { u: cred.u } : {}),
                    }, { sn: m1VcpIxnSn, d: m1VcpIxnSaid });

                    const m1IssEmbed = await buildCredentialEmbed(m1Client, g1HabM1, m1IssResult);
                    await m1Client.exchanges().send(
                        "m1", "registry", m1Hab, "/multisig/vcp",
                        { gid: g1Prefix, correlationId: corrId },
                        buildRegistryEmbed(m1RegResult), [m2Hab.prefix]
                    );
                    await m1Client.exchanges().send(
                        "m1", "multisig", m1Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId: corrId },
                        m1IssEmbed, [m2Hab.prefix]
                    );
                    console.log(
                        "[REPLAY][t=%dms] M1 broadcast VCP+ISS to M2, awaiting ops",
                        Date.now() - tFlowStart
                    );

                    // BLOCK until KERIA combines both partials (i.e. until M2 cosigns).
                    // This is the exact same `await Promise.all` from the wallet's
                    // initiateGroupIssuance path. M1's ISS op resolves the moment
                    // M2's ISS partial arrives at KERIA — that's the natural sync
                    // point that creates the ~1-2s gap between M2 and M1 ACKs.
                    await Promise.all([
                        waitOperation(m1Client, await m1RegResult.op()),
                        waitOperation(m1Client, m1IssResult.op),
                    ]);
                    console.log(
                        "[REPLAY][t=%dms] M1 Promise.all([VCP op, ISS op]) unblocked",
                        Date.now() - tFlowStart
                    );

                    // M1 sendGroupAck — exactly mirrors submitGroupResponseAndBroadcast
                    const [m1AckExn, m1AckSigs, m1AckAtc] = await m1Client.exchanges().createExchangeMessage(
                        g1HabM1, "/wap/iss/ack", ackPayload, {},
                        reqExn.exn.i, reqExn.exn.dt, reqExn.exn.d
                    );
                    m1AckSaid = m1AckExn.ked.d as string;
                    await m1Client.exchanges().sendFromEvents(
                        "G1v2", "wap", m1AckExn, m1AckSigs, m1AckAtc, [csHab.prefix]
                    );
                    m1AckSentAt = Date.now() - tFlowStart;
                    {
                        const seal = ["SealEvent", {
                            i: g1HabM1.prefix,
                            s: g1HabM1["state"]["ee"]["s"],
                            d: g1HabM1["state"]["ee"]["d"],
                        }];
                        const sigers = m1AckSigs.map((sig: string) => new Siger({ qb64: sig }));
                        const wrapIms = d(messagize(m1AckExn, sigers, seal));
                        const embAtc = wrapIms.substring(m1AckExn.size) + m1AckAtc;
                        await m1Client.exchanges().send(
                            "m1", "wap", m1Hab, "/multisig/exn",
                            { gid: g1HabM1.prefix }, { exn: [m1AckExn, embAtc] }, [m2Hab.prefix]
                        );
                    }
                    console.log(
                        "[REPLAY][t=%dms] M1 sent /wap/iss/ack partial + wrapper said=%s",
                        m1AckSentAt, m1AckSaid
                    );
                })(),

                // ────────────── M2 cosigner path ──────────────
                (async () => {
                    // Wait for /multisig/vcp + /multisig/iss to arrive from M1
                    const allExchanges = await pollAllIncomingExchanges(
                        m2Client, [corrId], m2Hab.prefix, 2, 90000
                    );
                    const vcpExch = allExchanges.find((e: any) => e.exn.r === "/multisig/vcp")!;
                    const issExch = allExchanges.find((e: any) => e.exn.r === "/multisig/iss")!;
                    console.log(
                        "[REPLAY][t=%dms] M2 received /multisig/vcp + /multisig/iss",
                        Date.now() - tFlowStart
                    );

                    // Simulate user-tap delay on M2. The wallet manual run was
                    // ~9.3s and triggered the FULL bug surface: dual-escrow on
                    // /wap/iss/ack PLUS dual-escrow on /multisig/vcp partials,
                    // which cascades into 'Tevery unescrow failed: Missing
                    // escrowed anchor' + 'Verifier unescrow failed: registry
                    // identifier ... not in Tevers' loops at 100% CPU.
                    // Setting 10s here so M2's /multisig/vcp partial reaches KERIA
                    // ~11s after M1's, matching the wallet's window.
                    const USER_TAP_MS = 10000;
                    await new Promise((r) => setTimeout(r, USER_TAP_MS));
                    console.log(
                        "[REPLAY][t=%dms] M2 user accepted (after %dms tap delay)",
                        Date.now() - tFlowStart, USER_TAP_MS
                    );

                    // Step 1: VCP cosign (drainQueuedVcpCosign)
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
                    // M2 waits for its OWN VCP op (this is what the wallet does in
                    // drainQueuedVcpCosign via waitAndGetDoneOp before the early-ACK).
                    await waitOperation(m2Client, await m2Reg.op());
                    console.log(
                        "[REPLAY][t=%dms] M2 VCP op resolved, firing early-ACK now",
                        Date.now() - tFlowStart
                    );

                    // Step 2: EARLY-ACK — submit M2's /wap/iss/ack partial BEFORE
                    // M2's ISS cosign. This is the wallet's drainQueuedIssCosign
                    // entry point. M2's partial enters KERIA's escrow ALONE and
                    // KERIA starts spinning [1] re-verify.
                    const [m2AckExn, m2AckSigs, m2AckAtc] = await m2Client.exchanges().createExchangeMessage(
                        g1HabM2, "/wap/iss/ack", ackPayload, {},
                        reqExn.exn.i, reqExn.exn.dt, reqExn.exn.d
                    );
                    expect(m2AckExn.ked.d).toBe(m1AckSaid || m2AckExn.ked.d);
                    await m2Client.exchanges().sendFromEvents(
                        "G1v2", "wap", m2AckExn, m2AckSigs, m2AckAtc, [csHab.prefix]
                    );
                    m2AckSentAt = Date.now() - tFlowStart;
                    {
                        const seal = ["SealEvent", {
                            i: g1HabM2.prefix,
                            s: g1HabM2["state"]["ee"]["s"],
                            d: g1HabM2["state"]["ee"]["d"],
                        }];
                        const sigers = m2AckSigs.map((sig: string) => new Siger({ qb64: sig }));
                        const wrapIms = d(messagize(m2AckExn, sigers, seal));
                        const embAtc = wrapIms.substring(m2AckExn.size) + m2AckAtc;
                        await m2Client.exchanges().send(
                            "m2", "wap", m2Hab, "/multisig/exn",
                            { gid: g1HabM2.prefix }, { exn: [m2AckExn, embAtc] }, [m1Hab.prefix]
                        );
                    }
                    console.log(
                        "[REPLAY][t=%dms] M2 sent /wap/iss/ack partial + wrapper said=%s",
                        m2AckSentAt, m2AckExn.ked.d
                    );

                    // Step 3: ISS cosign — this is what unblocks M1's Promise.all
                    // because KERIA combines M1+M2 ISS partials. M1 then sends its
                    // ACK, which arrives at KERIA while [1] is already spinning.
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
                    console.log(
                        "[REPLAY][t=%dms] M2 sent /multisig/iss cosign — unblocks M1's Promise.all",
                        Date.now() - tFlowStart
                    );
                    // Don't wait for M2's local ISS op here — the wallet does in
                    // drainQueuedIssCosign but for the repro it's not needed.
                })(),
            ]);

            const gapMs = m1AckSentAt - m2AckSentAt;
            console.log(
                "[REPLAY] both ACK partials sent. M2 at t=%dms, M1 at t=%dms, gap=%dms (wallet manual was ~1500ms)",
                m2AckSentAt, m1AckSentAt, gapMs
            );

            // ── Wait briefly for CS to receive /exn/wap/iss/ack. This is the
            //    happy-path signal — but it is NOT the assertion target because
            //    KERIA may eventually recover from the dual-escrow if given
            //    enough time. The actual bug surface is the partial-sig escrow
            //    PATTERN in KERIA's logs, which we inspect below. ──────────────
            const CS_DEADLINE_MS = 30_000;
            let csAckArrived = false;
            try {
                const [csAckNote] = await waitForNotificationsCount(
                    csClient, "/exn/wap/iss/ack", 1, CS_DEADLINE_MS
                );
                expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
                await csClient.notifications().mark(csAckNote.i);
                csAckArrived = true;
                console.log("[REPLAY] CS received /exn/wap/iss/ack credential=%s (KERIA recovered from dual-escrow)", credSaid);
            } catch {
                console.log("[REPLAY] CS did NOT receive /exn/wap/iss/ack within %dms — full bug surface (KERIA stuck)", CS_DEADLINE_MS);
            }

            await Promise.all([
                m1Client.notifications().mark(m1Note.i).catch(() => { }),
                m2Client.notifications().mark(m2Note.i).catch(() => { }),
            ]);

            // ── Inspect KERIA's container logs for the dual-escrow PATTERN.
            //    This IS the bug. Both `[0]` (M1's sig index) and `[1]` (M2's
            //    sig index) should appear in `Not enough signatures in [N]`
            //    lines for the same SAID — meaning KERIA tracked them as two
            //    separate escrow entries instead of merging into one. ─────────
            const keriaLogResult = spawnSync(
                "docker",
                ["logs", "private-veridian-wallet-keria-1"],
                { maxBuffer: 200 * 1024 * 1024 }
            );
            const keriaLog =
                (keriaLogResult.stdout?.toString() ?? "") +
                (keriaLogResult.stderr?.toString() ?? "");
            const keriaLines = keriaLog.split("\n");
            const teveryUnescrowFailed = keriaLines.filter(
                (l: string) => l.includes("Tevery unescrow failed")
            ).length;
            const teveryUnescrowError = keriaLines.filter(
                (l: string) => l.includes("Tevery unescrow error")
            ).length;
            const verifierUnescrowFailed = keriaLines.filter(
                (l: string) => l.includes("Verifier unescrow failed")
            ).length;
            const exchangePartiallyFailed = keriaLines.filter(
                (l: string) => l.includes("Exchange partially signed failed")
            ).length;

            console.log(
                "[REPLAY] KERIA cascade counts: " +
                "Tevery unescrow failed=%d, Tevery unescrow error=%d, " +
                "Verifier unescrow failed=%d, Exchange partially signed failed=%d",
                teveryUnescrowFailed, teveryUnescrowError, verifierUnescrowFailed, exchangePartiallyFailed
            );

            // Sample one of each cascade error for the dev to grep against
            const sampleTevery = keriaLines.find((l: string) => l.includes("Tevery unescrow failed"));
            const sampleVerifier = keriaLines.find((l: string) => l.includes("Verifier unescrow failed"));
            if (sampleTevery) console.log("[REPLAY] sample Tevery err: %s", sampleTevery.trim());
            if (sampleVerifier) console.log("[REPLAY] sample Verifier err: %s", sampleVerifier.trim());

            // Snapshot KERIA CPU after the test. In the wallet-freeze condition,
            // KERIA stays pinned at 100% CPU even minutes later because the
            // unescrow cascade has no backoff.
            const cpuResult = spawnSync(
                "docker",
                ["stats", "--no-stream", "--format", "{{.CPUPerc}}", "private-veridian-wallet-keria-1"],
                { maxBuffer: 1024 * 1024 }
            );
            const cpuPct = (cpuResult.stdout?.toString() ?? "").trim();
            console.log("[REPLAY] KERIA CPU after test: %s", cpuPct);

            const fullCascadeFired =
                teveryUnescrowFailed > 100 ||
                verifierUnescrowFailed > 100;

            if (fullCascadeFired) {
                console.log(
                    "[REPLAY] FULL WALLET BUG REPRODUCED: Tevery/Verifier unescrow cascade is firing. " +
                    "This is the same pattern as the wallet-observed freeze. " +
                    "Inspect KERIA logs for 'Missing escrowed anchor' and 'registry identifier ... not in Tevers'."
                );
            } else if (exchangePartiallyFailed > 0) {
                console.log(
                    "[REPLAY] PARTIAL BUG REPRODUCED: the ACK partial-sig escrow ran (%d times) but the " +
                    "Tevery/Verifier cascade did NOT fire (only %d + %d events). To get the full freeze, " +
                    "you likely need a longer M2 user-tap delay or to run on KERIA with residual stuck " +
                    "state from a prior failed run.",
                    exchangePartiallyFailed, teveryUnescrowFailed, verifierUnescrowFailed
                );
            } else {
                console.log(
                    "[REPLAY] No bug fired this run. " +
                    "ackArrived=%s. Try increasing USER_TAP_MS or re-running.",
                    csAckArrived
                );
            }

            // Assert the FULL wallet bug surface fired (cascade present). The
            // partial-sig escrow alone is not enough — that gets KERIA's logs
            // dirty but the eventual merge clears it. The cascade is what pegs
            // KERIA at 100% CPU forever in production.
            expect(fullCascadeFired).toBe(true);
        } finally {
            polling = false;
            await Promise.all(pollPromises);
            console.log(
                "[REPLAY] polls stopped. m1=%d m2=%d cs=%d holder=%d",
                pollStats.m1, pollStats.m2, pollStats.cs, pollStats.holder
            );
        }
    }, 240_000);

});
