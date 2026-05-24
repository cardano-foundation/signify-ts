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
        const res = await client.notifications().list();
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
                    client.exchanges().list({ filter: { "-r": route } }),
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
    let aliceClient: SignifyClient;

    let m1Hab: any;
    let m2Hab: any;
    let csHab: any;
    let aliceHab: any;
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
        [m1Client, m2Client, csClient, aliceClient] = await Promise.all([
            getClientFromFile("m1"),
            getClientFromFile("m2"),
            getClientFromFile("cs"),
            getClientFromFile("alice"),
        ]);
        [m1Hab, m2Hab, csHab, aliceHab, g1HabM1, g1HabM2] = await Promise.all([
            m1Client.identifiers().get("m1"),
            m2Client.identifiers().get("m2"),
            csClient.identifiers().get("cs"),
            aliceClient.identifiers().get("alice"),
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
            m1Client.notifications().list(),
            csClient.notifications().list(),
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
        const alicePrefix = aliceHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt1, attendeeName: "Alice OOR Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt2, attendeeName: "Alice OOR Flow2",
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
            // Two-phase because credentials().issue() requires the registry to be committed.
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

                // Wait for both registries to commit before ISS phase (registry existence constraint)
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
        const alicePrefix = aliceHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt1, attendeeName: "Alice ReverseOOR Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt2, attendeeName: "Alice ReverseOOR Flow2",
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
            // Wait for both VCP ops before phase 2, because credentials().issue() checks
            // that the target registry exists in KERIA at submission time.
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
        const alicePrefix = aliceHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt1, attendeeName: "Alice OOR3 Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];
        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt2, attendeeName: "Alice OOR3 Flow2",
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

                // Wait for VCP2 op — implies VCP1 committed + VCP2 cascaded → regk1+regk2 exist
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
});
