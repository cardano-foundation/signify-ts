/**
 * E2E test: WAP group issuance — two concurrent flows, ordered sequential processing.
 *
 * Actors: same as wap-group-issuance-ordered.test.ts (M1, M2, G1, CS, Alice).
 *
 * Flow:
 *   CS sends two concurrent /wap/iss requests (flow1, flow2).
 *   M1 processes them sequentially: VCP1 → ISS1 → VCP2 → ISS2 with explicit anchorPoint chaining.
 *   M2 handles multisig exchanges one-by-one as they arrive, in KEL sequence order.
 *   M1 submits ACKs for both flows with combined sigs.
 *   CS receives two /exn/wap/iss/ack notifications.
 *
 * Why harder than the single-flow ordered test:
 *   - M1 must chain anchorPoints explicitly across flows: VCP2 anchors after ISS1's ixn.
 *   - M2 must sort across two correlationIds and process one exchange at a time without
 *     knowing the sn chain ahead of time.
 *   - KERIA commits 4 ixn events before CS receives two ACKs.
 *
 * KEL chain (group starts at sn X):
 *   ixn(X+1) = VCP1 anchor
 *   ixn(X+2) = ISS1 anchor  (anchorPoint = { sn: X+1, d: vcp1Ixn.d })
 *   ixn(X+3) = VCP2 anchor  (anchorPoint = { sn: X+2, d: iss1Ixn.d })
 *   ixn(X+4) = ISS2 anchor  (anchorPoint = { sn: X+3, d: vcp2Ixn.d })
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

// Polls until at least `minCount` unread notifications with the given route are present.
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

// Polls exchange lists for the first exchange matching any of the given correlationIds
// that has not yet been processed (SAID not in `processed`).
// excludeSender: skip exchanges where exn.i equals this prefix (M2's own outgoing exchanges
// appear in M2's exchange list and must be excluded to avoid reprocessing).
// Returns the lowest-sn unprocessed exchange across /multisig/vcp and /multisig/iss.
async function pollNextUnprocessed(
    client: SignifyClient,
    corrIds: string[],
    processed: Set<string>,
    excludeSender?: string,
    timeoutMs = 90000
): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    let attempt = 0;
    while (Date.now() < deadline) {
        const candidates: any[] = [];
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
                    !processed.has(x.exn.d) &&
                    (!excludeSender || x.exn.i !== excludeSender)
            );
            candidates.push(...filtered);
        }
        if (candidates.length > 0) {
            candidates.sort(
                (a: any, b: any) =>
                    parseInt(a.exn.e?.anc?.s ?? "0", 16) -
                    parseInt(b.exn.e?.anc?.s ?? "0", 16)
            );
            if (attempt > 0) {
                console.log(
                    "[POLL] found unprocessed exchange: route=%s anc.s=%s (attempt=%d)",
                    candidates[0].exn.r,
                    candidates[0].exn.e?.anc?.s,
                    attempt
                );
            }
            return candidates[0];
        }
        attempt++;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout: no unprocessed exchange for corrIds=[${corrIds.join(",")}] (processed=${processed.size})`
    );
}

const clientsPath = path.join(__dirname, "../../examples/.test-clients.json");
const groupPath = path.join(__dirname, "../../examples/.test-group.json");

describe("WAP group issuance E2E (ordered phases, two concurrent flows)", () => {
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

    it("multi-flow ordered: VCP1/ISS1/VCP2/ISS2 chained — CS receives two /exn/wap/iss/ack", async () => {
        const nonce1 = randomNonce();
        const nonce2 = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const alicePrefix = aliceHab.prefix;
        const regk1 = computeRegk(g1Prefix, nonce1);
        const regk2 = computeRegk(g1Prefix, nonce2);

        // ── CS sends two /wap/iss concurrently ────────────────────────────────
        const dt1 = signifyDatetime();
        const aBlock1 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt1, attendeeName: "Alice Flow1",
        })[1];
        const acdcSad1 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk1,
            s: SCHEMA_SAID, a: aBlock1,
        })[1];

        const dt2 = signifyDatetime();
        const aBlock2 = Saider.saidify({
            d: "", i: alicePrefix, dt: dt2, attendeeName: "Alice Flow2",
        })[1];
        const acdcSad2 = Saider.saidify({
            v: "ACDC10JSON000000_", d: "", i: g1Prefix, ri: regk2,
            s: SCHEMA_SAID, a: aBlock2,
        })[1];

        const wapIssDt1 = signifyDatetime();
        const wapIssDt2 = signifyDatetime();

        const [[csExn1, csSigs1, csAtc1], [csExn2, csSigs2, csAtc2]] = await Promise.all([
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss",
                { n: nonce1, l: [acdcSad1] },
                {}, g1Prefix, wapIssDt1
            ),
            csClient.exchanges().createExchangeMessage(
                csHab, "/wap/iss",
                { n: nonce2, l: [acdcSad2] },
                {}, g1Prefix, wapIssDt2
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
        console.log("[M1] got %d /exn/wap/iss notifications", m1Notes.length);

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
        console.log("[M1] corrId1=...%s corrId2=...%s", corrId1.slice(-8), corrId2.slice(-8));

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

        // ── M1 sequential + M2 per-exchange concurrently ──────────────────────
        console.log("[TEST] Starting M1/M2 concurrent phase (4 exchanges total)");

        await Promise.all([
            // M1: VCP1 → ISS1 → VCP2 (anchored on ISS1) → ISS2 (anchored on VCP2)
            (async () => {
                // VCP1 — uses current group state as anchorPoint
                const regResult1 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce1}`,
                    nonce: nonce1,
                });
                const vcp1Op = await regResult1.op();
                const vcp1IxnSn = parseInt(regResult1.serder.ked.s, 16);
                const vcp1IxnSaid = regResult1.serder.ked.d;
                console.log("[M1] VCP1 created: ixnSn=%d", vcp1IxnSn);

                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId1 },
                    buildRegistryEmbed(regResult1), [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/vcp flow1");
                await waitOperation(m1Client, vcp1Op);
                console.log("[M1] VCP1 op done");

                // ISS1 — anchors on VCP1 ixn
                const iss1Result = await m1Client.credentials().issue(
                    "G1v2", issParams1, { sn: vcp1IxnSn, d: vcp1IxnSaid }
                );
                const iss1AncSn = iss1Result.anc.sn;
                const iss1AncSaid = iss1Result.anc.ked.d;
                console.log("[M1] ISS1 issued: ixnSn=%d", iss1AncSn);

                const issEmbed1 = await buildCredentialEmbed(m1Client, g1HabM1, iss1Result);
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId1 },
                    issEmbed1, [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/iss flow1");
                await waitOperation(m1Client, iss1Result.op);
                console.log("[M1] ISS1 op done");

                // VCP2 — explicitly anchors after ISS1's ixn
                const regResult2 = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce2}`,
                    nonce: nonce2,
                    anchorPoint: { sn: iss1AncSn, d: iss1AncSaid },
                });
                const vcp2Op = await regResult2.op();
                const vcp2IxnSn = parseInt(regResult2.serder.ked.s, 16);
                const vcp2IxnSaid = regResult2.serder.ked.d;
                console.log("[M1] VCP2 created: ixnSn=%d (anchored after ISS1 sn=%d)", vcp2IxnSn, iss1AncSn);

                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId: corrId2 },
                    buildRegistryEmbed(regResult2), [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/vcp flow2");
                await waitOperation(m1Client, vcp2Op);
                console.log("[M1] VCP2 op done");

                // ISS2 — anchors on VCP2 ixn
                const iss2Result = await m1Client.credentials().issue(
                    "G1v2", issParams2, { sn: vcp2IxnSn, d: vcp2IxnSaid }
                );
                console.log("[M1] ISS2 issued: ixnSn=%d", iss2Result.anc.sn);

                const issEmbed2 = await buildCredentialEmbed(m1Client, g1HabM1, iss2Result);
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId: corrId2 },
                    issEmbed2, [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/iss flow2");
                await waitOperation(m1Client, iss2Result.op);
                console.log("[M1] ISS2 op done — all 4 ixn events committed");
            })(),

            // M2: process each exchange as it arrives, in anc.s order across both flows
            (async () => {
                const processed = new Set<string>();

                for (let i = 0; i < 4; i++) {
                    const exchange = await pollNextUnprocessed(
                        m2Client, [corrId1, corrId2], processed, m2Hab.prefix
                    );
                    processed.add(exchange.exn.d);

                    const ancFull = exchange.exn.e?.anc as { s: string; p: string };
                    const targetSn = parseInt(ancFull.s, 16);
                    const anchorPoint = { sn: targetSn - 1, d: ancFull.p };
                    const corrId = exchange.exn.a?.correlationId as string;
                    const isFlow1 = corrId === corrId1;

                    console.log(
                        "[M2] processing %d/4: route=%s flow=%d targetSn=%d",
                        i + 1, exchange.exn.r, isFlow1 ? 1 : 2, targetSn
                    );

                    if (exchange.exn.r === "/multisig/vcp") {
                        const nonce = isFlow1 ? nonce1 : nonce2;
                        const regName = isFlow1
                            ? `wap-registry-${nonce1}`
                            : `wap-registry-${nonce2}`;
                        const m2VcpResult = await m2Client.registries().create({
                            name: "G1v2",
                            registryName: regName,
                            nonce,
                            anchorPoint,
                        });
                        await m2Client.exchanges().send(
                            "m2", "registry", m2Hab, "/multisig/vcp",
                            { gid: g1Prefix, correlationId: corrId },
                            buildRegistryEmbed(m2VcpResult), [m1Hab.prefix]
                        );
                        await waitOperation(m2Client, await m2VcpResult.op());
                        console.log("[M2] VCP co-signed: flow=%d sn=%d", isFlow1 ? 1 : 2, targetSn);
                    } else {
                        const acdc = exchange.exn.e?.acdc as Record<string, unknown>;
                        const iss = exchange.exn.e?.iss as { ri: string };
                        const m2IssResult = await m2Client.credentials().issue("G1v2", {
                            i: g1Prefix,
                            ri: iss.ri,
                            s: acdc.s as string,
                            a: acdc.a as Record<string, unknown>,
                            ...(acdc.u ? { u: acdc.u as string } : {}),
                        }, anchorPoint);
                        const issEmbed = await buildCredentialEmbed(m2Client, g1HabM2, m2IssResult);
                        await m2Client.exchanges().send(
                            "m2", "multisig", m2Hab, "/multisig/iss",
                            { gid: g1Prefix, correlationId: corrId },
                            issEmbed, [m1Hab.prefix]
                        );
                        await waitOperation(m2Client, m2IssResult.op);
                        console.log("[M2] ISS co-signed: flow=%d sn=%d", isFlow1 ? 1 : 2, targetSn);
                    }
                }
                console.log("[M2] all 4 exchanges processed");
            })(),
        ]);

        console.log("[TEST] all phases done — waiting before ACK");
        await new Promise((r) => setTimeout(r, 3000));

        // ── ACK both flows (combined sigs, one submission per flow) ───────────
        console.log("[TEST] Phase ACK: sending ACK for flow1");
        const [[ackExn1, ackSigs1_1], [, ackSigs1_2]] = await Promise.all([
            m1Client.exchanges().createExchangeMessage(
                g1HabM1, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req1.exn.d },
                {}, req1.exn.i, req1.exn.dt, req1.exn.d
            ),
            m2Client.exchanges().createExchangeMessage(
                g1HabM2, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req1.exn.d },
                {}, req1.exn.i, req1.exn.dt, req1.exn.d
            ),
        ]);
        await m1Client.exchanges().sendFromEvents(
            "G1v2", "wap", ackExn1, [...ackSigs1_1, ...ackSigs1_2], "", [csHab.prefix]
        );
        console.log("[M1] ACK1 submitted: said=%s", ackExn1.ked.d);
        await m1Client.notifications().mark(note1.i);

        console.log("[TEST] Phase ACK: sending ACK for flow2");
        const [[ackExn2, ackSigs2_1], [, ackSigs2_2]] = await Promise.all([
            m1Client.exchanges().createExchangeMessage(
                g1HabM1, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req2.exn.d },
                {}, req2.exn.i, req2.exn.dt, req2.exn.d
            ),
            m2Client.exchanges().createExchangeMessage(
                g1HabM2, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: req2.exn.d },
                {}, req2.exn.i, req2.exn.dt, req2.exn.d
            ),
        ]);
        await m1Client.exchanges().sendFromEvents(
            "G1v2", "wap", ackExn2, [...ackSigs2_1, ...ackSigs2_2], "", [csHab.prefix]
        );
        console.log("[M1] ACK2 submitted: said=%s", ackExn2.ked.d);
        await m1Client.notifications().mark(note2.i);

        // ── CS receives both /exn/wap/iss/ack ─────────────────────────────────
        console.log("[TEST] Waiting for CS to receive 2x /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotificationsCount(csClient, "/exn/wap/iss/ack", 2, 60000);
        console.log("[CS] received %d ACK(s)", csAckNotes.length);
        expect(csAckNotes).toHaveLength(2);
        for (const note of csAckNotes) {
            expect(note.a.r).toBe("/exn/wap/iss/ack");
        }
    }, 300000);
});
