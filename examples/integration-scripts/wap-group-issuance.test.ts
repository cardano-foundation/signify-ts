/**
 * E2E test: WAP group issuance flow with real KERIA.
 *
 * Actors:
 *   M1  — group member 1 (initiator)
 *   M2  — group member 2 (cosigner)
 *   G1  — 2-of-2 multisig group formed by M1 + M2
 *   CS  — credential server (sends /wap/iss to G1)
 *   Alice — holder (receives the credential)
 *
 * Flow:
 *   1. CS sends /wap/iss exchange to G1
 *   2. M1 (initiator): creates VCP registry, issues credentials, sends
 *      /multisig/vcp + /multisig/iss exchanges, sends /multisig/exn (ACK)
 *   3. M2 (cosigner): queries VCP+ISS exchanges by correlationId, co-signs
 *      each one, sends /multisig/exn (ACK)
 *   4. KERIA counselor assembles both ACK signatures → delivers /exn/wap/iss/ack to CS
 *
 * Prerequisites:
 *   1. docker-compose down -v && docker-compose up -d   (clean KERIA volume)
 *   2. cd signify-ts && npx tsx examples/integration-scripts/utils/setup-all.ts
 *      (generates .test-clients.json, .test-group.json, .test-contacts.json)
 *
 * Run:
 *   cd signify-ts && TEST_ENVIRONMENT=local npx jest examples/integration-scripts/wap-group-issuance.test.ts
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
import {
    waitForNotifications,
    waitOperation,
} from "./utils/test-util";
import fs from "fs";
import path from "path";

// ─── schema ──────────────────────────────────────────────────────────────────
const SCHEMA_SAID = "EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb"; // Rare Evo demo

// ─── helpers matching issuanceService.ts logic ────────────────────────────────

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

// Poll exchanges via exchanges().list({filter}) — same pattern as the wallet's
// issuanceService.ts. /multisig/vcp and /multisig/iss are stored as regular exchanges
// (not group requests), so list+filter is the correct API.
async function pollExchangesByNotif(
    client: SignifyClient,
    route: string,
    correlationId: string,
    minCount: number,
    timeoutMs = 60000
): Promise<any[]> {
    // Use only -r filter (no nested -a-correlationId), apply correlationId client-side.
    // KERIA appears to hang on the nested filter for /multisig/iss specifically.
    const filter = { "-r": route };
    const deadline = Date.now() + timeoutMs;
    let attempt = 0;
    while (Date.now() < deadline) {
        let raw: any[] = [];
        let listErr: string | undefined;
        try {
            raw = (await Promise.race([
                client.exchanges().list({ filter }),
                new Promise<any[]>((_, rej) =>
                    setTimeout(() => rej(new Error("list timeout 10s")), 10000)
                ),
            ])) ?? [];
        } catch (err: any) {
            listErr = String(err?.message ?? err);
        }
        const filtered = raw.filter(
            (x: any) => x.exn.a?.correlationId === correlationId
        );
        if (attempt === 0 || filtered.length > 0) {
            console.log(
                "[POLL] attempt=%d route=%s raw=%d filtered=%d want=%d err=%s",
                attempt, route, raw.length, filtered.length, minCount, listErr ?? "none"
            );
        }
        if (filtered.length >= minCount) return filtered;
        attempt++;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout waiting for ${minCount} exchanges (route=${route} correlationId=${correlationId})`
    );
}

// ─── test ─────────────────────────────────────────────────────────────────────

async function getClientFromFile(name: string): Promise<SignifyClient> {
    const filePath = path.join(__dirname, '../../examples/.test-clients.json');
    const clientsData = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    const data = clientsData[name];
    if (!data) throw new Error(`Client ${name} not found in .test-clients.json`);

    const clientEnv = resolveEnvironment();
    await ready();
    const client = new SignifyClient(clientEnv.url, data.bran, Tier.low, clientEnv.bootUrl);
    try {
        await client.connect();
    } catch {
        // Agent doesn't exist in KERIA — boot it first (fresh KERIA state)
        await client.boot();
        await client.connect();
    }
    return client;
}

// ─── test files ───────────────────────────────────────────────────────────────

const clientsPath = path.join(__dirname, '../../examples/.test-clients.json');
const groupPath = path.join(__dirname, '../../examples/.test-group.json');

describe("Setup verification", () => {
    it("clients file should exist", () => {
        expect(fs.existsSync(clientsPath)).toBe(true);
        const clients = JSON.parse(fs.readFileSync(clientsPath, 'utf-8'));
        expect(clients.m1).toBeDefined();
        expect(clients.m2).toBeDefined();
        expect(clients.cs).toBeDefined();
        expect(clients.alice).toBeDefined();
        console.log("\n=== Clients ===");
        console.log(`m1: ${clients.m1.prefix} (agent: ${clients.m1.agent})`);
        console.log(`m2: ${clients.m2.prefix} (agent: ${clients.m2.agent})`);
        console.log(`cs: ${clients.cs.prefix} (agent: ${clients.cs.agent})`);
        console.log(`alice: ${clients.alice.prefix} (agent: ${clients.alice.agent})`);
    });

    it("contacts should exist between all participants", async () => {
        const [m1Client, m2Client, csClient, aliceClient] = await Promise.all([
            getClientFromFile('m1'),
            getClientFromFile('m2'),
            getClientFromFile('cs'),
            getClientFromFile('alice'),
        ]);

        const [m1Hab, m2Hab, csHab, aliceHab] = await Promise.all([
            m1Client.identifiers().get('m1'),
            m2Client.identifiers().get('m2'),
            csClient.identifiers().get('cs'),
            aliceClient.identifiers().get('alice'),
        ]);

        console.log("\n=== Contacts ===");

        const m1Contacts = await m1Client.contacts().list();
        console.log(`M1 contacts (${m1Contacts.length}):`);
        for (const c of m1Contacts) console.log(`  ${c.alias}: ${c.id}`);

        const m2Contacts = await m2Client.contacts().list();
        console.log(`M2 contacts (${m2Contacts.length}):`);
        for (const c of m2Contacts) console.log(`  ${c.alias}: ${c.id}`);

        const csContacts = await csClient.contacts().list();
        console.log(`CS contacts (${csContacts.length}):`);
        for (const c of csContacts) console.log(`  ${c.alias}: ${c.id}`);

        const aliceContacts = await aliceClient.contacts().list();
        console.log(`Alice contacts (${aliceContacts.length}):`);
        for (const c of aliceContacts) console.log(`  ${c.alias}: ${c.id}`);

        expect(m1Contacts.length).toBeGreaterThan(0);
        expect(m2Contacts.length).toBeGreaterThan(0);
        expect(csContacts.length).toBeGreaterThan(0);
        expect(aliceContacts.length).toBeGreaterThanOrEqual(0);
    });

    it("multisig group G1v2 should exist", async () => {
        const [m1Client, m2Client] = await Promise.all([
            getClientFromFile('m1'),
            getClientFromFile('m2'),
        ]);

        const g1M1 = await m1Client.identifiers().get('G1v2');
        const g1M2 = await m2Client.identifiers().get('G1v2');
        const prefix = g1M1.prefix;

        console.log("\n=== Group ===");
        console.log(`name: G1v2`);
        console.log(`prefix: ${prefix}`);

        expect(g1M1.prefix).toBe(g1M2.prefix);
        console.log(`Verified: G1v2 prefix matches in both M1 and M2`);
    });
});

describe("WAP group issuance E2E", () => {
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
                `Clients file not found at ${clientsPath}. Run setup-all.ts first:\n` +
                `  npx tsx examples/integration-scripts/utils/setup-all.ts`
            );
        }
        if (!fs.existsSync(groupPath)) {
            throw new Error(
                `Group file not found at ${groupPath}. Run setup-all.ts first:\n` +
                `  npx tsx examples/integration-scripts/utils/setup-all.ts`
            );
        }
        // env is destructured to silence unused-variable warning while keeping the import
        void env;

        console.log("[SETUP] Connecting to clients from .test-clients.json...");
        [m1Client, m2Client, csClient, aliceClient] = await Promise.all([
            getClientFromFile('m1'),
            getClientFromFile('m2'),
            getClientFromFile('cs'),
            getClientFromFile('alice'),
        ]);
        console.log("[SETUP] Loading identifiers...");
        [m1Hab, m2Hab, csHab, aliceHab, g1HabM1, g1HabM2] = await Promise.all([
            m1Client.identifiers().get("m1"),
            m2Client.identifiers().get("m2"),
            csClient.identifiers().get("cs"),
            aliceClient.identifiers().get("alice"),
            m1Client.identifiers().get("G1v2"),
            m2Client.identifiers().get("G1v2"),
        ]);
        console.log("[SETUP] m1=%s m2=%s cs=%s alice=%s G1=%s",
            m1Hab.prefix, m2Hab.prefix, csHab.prefix, aliceHab.prefix, g1HabM1.prefix);

        // Sanity: CS must have G1 contact and members must have CS contact
        const [csG1, m1Cs, m2Cs] = await Promise.all([
            csClient.contacts().get(g1HabM1.prefix).catch(() => null),
            m1Client.contacts().get(csHab.prefix).catch(() => null),
            m2Client.contacts().get(csHab.prefix).catch(() => null),
        ]);
        if (!csG1 || !m1Cs || !m2Cs) {
            throw new Error(
                `Contacts missing (csG1=${!!csG1} m1Cs=${!!m1Cs} m2Cs=${!!m2Cs}). ` +
                `Re-run setup-all.ts.`
            );
        }
        console.log("[SETUP] Contacts ok");
    }, 60000);

    it("M1 + M2 co-sign WAP issuance and CS receives ACK", async () => {
        const nonce = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const alicePrefix = aliceHab.prefix;
        const regk = computeRegk(g1Prefix, nonce);

        // ── CS builds and sends /wap/iss ──────────────────────────────────────
        const dt = signifyDatetime();
        const aBlock = Saider.saidify({
            d: "",
            i: alicePrefix,
            dt,
            attendeeName: "Alice Test",
        })[1];
        const acdcSad = Saider.saidify({
            v: "ACDC10JSON000000_",
            d: "",
            i: g1Prefix,
            ri: regk,
            s: SCHEMA_SAID,
            a: aBlock,
        })[1];

        const wapIssDt = signifyDatetime();
        const [exn, sigs, atc] = await csClient
            .exchanges()
            .createExchangeMessage(
                csHab,
                "/wap/iss",
                { n: nonce, l: [acdcSad] },
                {},
                g1Prefix,
                wapIssDt
            );
        const wapIssSaid = exn.ked.d;

        await csClient
            .exchanges()
            .sendFromEvents("cs", "iss", exn, sigs, atc, [g1Prefix]);
        console.log("[TEST] CS sent /wap/iss: said=%s to G1=%s", wapIssSaid, g1Prefix);

        // Diagnostic: check M1+M2 notification state before waiting
        const [m1NotifsPreWait, m2NotifsPreWait] = await Promise.all([
            m1Client.notifications().list(),
            m2Client.notifications().list(),
        ]);
        console.log("[TEST] M1 notifications before wait: count=%d routes=%s",
            m1NotifsPreWait.notes?.length ?? 0,
            m1NotifsPreWait.notes?.map((n: any) => n.a.r).join("|") ?? "none");
        console.log("[TEST] M2 notifications before wait: count=%d routes=%s",
            m2NotifsPreWait.notes?.length ?? 0,
            m2NotifsPreWait.notes?.map((n: any) => n.a.r).join("|") ?? "none");

        const m1NoteList = await waitForNotifications(m1Client, "/exn/wap/iss", { timeout: 30000 });
        const m1Note = m1NoteList[0];
        console.log("[TEST] M1 got /exn/wap/iss: notifSaid=%s exchSaid=%s", m1Note.i, m1Note.a.d);

        const m1RequestExn = await m1Client.exchanges().get(m1Note.a.d!);
        const payload = m1RequestExn.exn.a as { n: string; l: any[] };
        const correlationId: string = m1RequestExn.exn.d;
        expect(correlationId).toBe(wapIssSaid);
        console.log("[TEST] correlationId=%s credCount=%d", correlationId, payload.l.length);

        // M1 + M2 run as concurrent async tasks (simulating independent wallet processes).
        // Phase 1: M1 sends /multisig/vcp; M2 polls + co-signs + sends back.
        // Phase 2: M1 awaits its VCP op (completes when M2 has co-signed), then issues
        //          credential + sends /multisig/iss; M2 polls + co-signs + sends back.
        // Phase 3: Both await all their ops, then send /multisig/exn (ACK).
        const m1Ops: any[] = [];
        const m2Ops: any[] = [];
        let ackExn1Said: string | null = null;
        let m1AckExn: any = null;
        let m1AckSigs: string[] = [];
        let m2AckSigs: string[] = [];

        const m1Flow = async (): Promise<void> => {
            // Phase 1: create VCP and send to M2
            const regResult = await m1Client.registries().create({
                name: "G1v2",
                registryName: `wap-registry-${nonce}`,
                nonce,
            });
            const m1VcpOp = await regResult.op();
            m1Ops.push(m1VcpOp);
            const vcpIxnSn = parseInt(regResult.serder.ked.s, 16);
            console.log("[M1] created VCP: ixnSn=%d ixnSaid=%s", vcpIxnSn, regResult.serder.ked.d);

            const vcpEmbed = buildRegistryEmbed(regResult);
            await m1Client.exchanges().send(
                "m1", "registry", m1Hab, "/multisig/vcp",
                { gid: g1Prefix, correlationId },
                vcpEmbed, [m2Hab.prefix]
            );
            console.log("[M1] sent /multisig/vcp");

            // Wait for VCP op to complete (i.e. M2 has co-signed) before issuing creds
            console.log("[M1] awaiting VCP op...");
            await waitOperation(m1Client, m1VcpOp);
            console.log("[M1] VCP op complete");

            // Phase 2: issue each cred and send /multisig/iss
            let anchor = { sn: vcpIxnSn, d: regResult.serder.ked.d };
            for (const [i, cred] of payload.l.entries()) {
                const issParams = {
                    i: g1Prefix,
                    ri: regk,
                    s: cred.s,
                    a: cred.a,
                    ...(cred.u ? { u: cred.u } : {}),
                };
                console.log("[M1] issuing cred[%d]: anchorBase=%d targetSn=%d",
                    i, anchor.sn, anchor.sn + 1);
                const issResult = await m1Client.credentials().issue("G1v2", issParams, anchor);
                m1Ops.push(issResult.op);
                console.log("[M1] cred[%d] issued: anc.sn=%d", i, issResult.anc?.sn);

                const issEmbed = await buildCredentialEmbed(m1Client, g1HabM1, issResult);
                await m1Client.exchanges().send(
                    "m1", "multisig", m1Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId },
                    issEmbed, [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/iss[%d]", i);
                // Don't wait for the ISS op here: while KERIA processes M2's co-sign
                // exchange on M1's agent, operations().get() can block on an internal
                // lock. The ACK exchange doesn't reference any credential SAID, so M1
                // can proceed to Phase 3 without waiting. M2's co-sign completes the
                // op in the background.

                anchor = { sn: issResult.anc.sn, d: issResult.anc.ked.d };
            }

            // Phase 3: collect M1's ACK sig (combined submission happens after Promise.all)
            const [ackExn1, ackSigs1] = await m1Client.exchanges().createExchangeMessage(
                g1HabM1, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {}, m1RequestExn.exn.i, m1RequestExn.exn.dt, m1RequestExn.exn.d
            );
            ackExn1Said = ackExn1.ked.d;
            m1AckExn = ackExn1;
            m1AckSigs = ackSigs1;
            console.log("[M1] ACK sig ready: said=%s", ackExn1.ked.d);
            await m1Client.notifications().mark(m1Note.i);
        };

        const m2Flow = async (): Promise<void> => {
            // Phase 1: wait for /multisig/vcp, co-sign, send back
            console.log("[M2] polling /multisig/vcp...");
            const vcpExchanges = await pollExchangesByNotif(
                m2Client, "/multisig/vcp", correlationId, 1
            );
            console.log("[M2] got /multisig/vcp: count=%d", vcpExchanges.length);
            expect(vcpExchanges.length).toBe(1);

            const vcpExchange = vcpExchanges[0];
            const vcpAncFull = vcpExchange.exn.e?.anc as { s: string; p: string };
            const vcpTargetSn = parseInt(vcpAncFull.s, 16);
            const vcpAnchor = { sn: vcpTargetSn - 1, d: vcpAncFull.p };
            console.log("[M2] co-signing VCP: targetSn=%d ancPrior=%s",
                vcpTargetSn, vcpAnchor.d);

            const vcpResult = await m2Client.registries().create({
                name: "G1v2",
                registryName: `wap-registry-${nonce}`,
                nonce,
                anchorPoint: vcpAnchor,
            });
            const m2VcpOp = await vcpResult.op();
            m2Ops.push(m2VcpOp);
            expect(parseInt(vcpResult.serder.ked.s, 16)).toBe(vcpTargetSn);

            const vcpEmbed2 = buildRegistryEmbed(vcpResult);
            await m2Client.exchanges().send(
                "m2", "registry", m2Hab, "/multisig/vcp",
                { gid: g1Prefix, correlationId },
                vcpEmbed2, [m1Hab.prefix]
            );
            console.log("[M2] sent /multisig/vcp back");

            // Wait for VCP op so M2's view of group is at sn+1 before processing iss
            await waitOperation(m2Client, m2VcpOp);
            console.log("[M2] VCP op complete");

            // Phase 2: poll /multisig/iss, co-sign each
            console.log("[M2] polling /multisig/iss want=%d...", payload.l.length);
            const issExchanges = (await pollExchangesByNotif(
                m2Client, "/multisig/iss", correlationId, payload.l.length
            )).sort((a: any, b: any) =>
                parseInt(a.exn.e?.anc?.s ?? "0", 16) - parseInt(b.exn.e?.anc?.s ?? "0", 16)
            );
            console.log("[M2] got /multisig/iss: count=%d", issExchanges.length);
            expect(issExchanges.length).toBe(payload.l.length);

            for (const [i, issExchange] of issExchanges.entries()) {
                const acdc = issExchange.exn.e?.acdc as Record<string, unknown>;
                const iss = issExchange.exn.e?.iss as { ri: string };
                const issAncFull = issExchange.exn.e?.anc as { s: string; p: string };
                const issTargetSn = parseInt(issAncFull.s, 16);
                const issAnchor = { sn: issTargetSn - 1, d: issAncFull.p };
                console.log("[M2] co-signing ISS[%d]: targetSn=%d", i, issTargetSn);

                const issResult = await m2Client.credentials().issue("G1v2", {
                    i: g1Prefix,
                    ri: iss.ri,
                    s: acdc.s as string,
                    a: acdc.a as Record<string, unknown>,
                    ...(acdc.u ? { u: acdc.u as string } : {}),
                }, issAnchor);
                m2Ops.push(issResult.op);
                expect(issResult.anc?.sn).toBe(issTargetSn);

                const issEmbed2 = await buildCredentialEmbed(m2Client, g1HabM2, issResult);
                await m2Client.exchanges().send(
                    "m2", "multisig", m2Hab, "/multisig/iss",
                    { gid: g1Prefix, correlationId },
                    issEmbed2, [m1Hab.prefix]
                );
                console.log("[M2] sent /multisig/iss[%d] back", i);

                await waitOperation(m2Client, issResult.op);
                console.log("[M2] iss[%d] op complete", i);
            }

            // Phase 3: collect M2's ACK sig (combined submission happens after Promise.all)
            console.log("[M2] building ACK exn...");
            const [ackExn2, ackSigs2] = await m2Client.exchanges().createExchangeMessage(
                g1HabM2, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {}, m1RequestExn.exn.i, m1RequestExn.exn.dt, m1RequestExn.exn.d
            );
            m2AckSigs = ackSigs2;
            console.log("[M2] ACK sig ready: said=%s", ackExn2.ked.d);
            if (ackExn1Said !== null) {
                expect(ackExn2.ked.d).toBe(ackExn1Said); // deterministic SAID
            }
        };

        console.log("[TEST] Running M1 and M2 flows in parallel...");
        await Promise.all([m1Flow(), m2Flow()]);
        console.log("[TEST] Both flows complete. m1Ops=%d m2Ops=%d", m1Ops.length, m2Ops.length);

        // Submit ACK with both sigs from M1's agent. KERIA sees 2/2 threshold met
        // immediately → exchange in exns → WapackSender fires (M1 is lead: index 0).
        await m1Client.exchanges().sendFromEvents(
            "G1v2", "wap",
            m1AckExn,
            [...m1AckSigs, ...m2AckSigs],
            "",
            [csHab.prefix]
        );
        console.log("[M1] submitted ACK with both sigs: said=%s", m1AckExn.ked.d);

        // ── Verify CS receives ACK ────────────────────────────────────────────
        // Diagnostic: check CS notifs before waiting
        const csNotifsBeforeAck = await csClient.notifications().list();
        console.log("[TEST] CS notifs before ACK wait: count=%d routes=%s",
            csNotifsBeforeAck.notes?.length ?? 0,
            csNotifsBeforeAck.notes?.map((n: any) => n.a.r).join("|") ?? "none");

        console.log("[TEST] Waiting for CS to receive /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotifications(csClient, "/exn/wap/iss/ack", {
            timeout: 60000,
        });
        const csAckNote = csAckNotes[0];
        console.log("[TEST] CS received ACK: notifId=%s exchSaid=%s route=%s",
            csAckNote?.i, csAckNote?.a?.d, csAckNote?.a?.r);
        expect(csAckNote).toBeDefined();
        expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
    }, 300000);
});
