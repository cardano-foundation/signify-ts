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
 * Run against docker-compose KERIA:
 *   cd signify-ts && TEST_ENVIRONMENT=local npx jest examples/integration-scripts/wap-group-issuance.test.ts
 */

import {
    Algos,
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
} from "signify-ts";
import { resolveEnvironment } from "./utils/resolve-env";
import {
    getOrCreateClient,
    getOrCreateIdentifier,
    waitAndMarkNotification,
    waitForNotifications,
    waitOperation,
} from "./utils/test-util";

// ─── schema ──────────────────────────────────────────────────────────────────
const SCHEMA_SAID = "EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb"; // Rare Evo demo
// KERIA (inside Docker) fetches this URL, so use the Docker-internal hostname.
// Override with SCHEMA_BASE_URL env var if needed.
const SCHEMA_BASE_URL =
    process.env.SCHEMA_BASE_URL ?? "http://cred-issuance:3001";

// ─── OOBI hostname rewrite ────────────────────────────────────────────────────
// KERIA inside Docker advertises its own container hostname (keria:3902,
// witness-demo:5642...) in OOBIs. When running tests on the host with
// TEST_ENVIRONMENT=local we must rewrite those to localhost equivalents since
// the docker port bindings map them 1-to-1.
function rewriteOobi(oobi: string, preset: string): string {
    if (preset !== "local") return oobi;
    return oobi
        .replace(/http:\/\/keria:/g, "http://127.0.0.1:")
        .replace(/http:\/\/witness-demo:/g, "http://127.0.0.1:");
}

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

async function pollExchanges(
    client: SignifyClient,
    filter: Record<string, string>,
    minCount: number,
    correlationId: string,
    timeoutMs = 60000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        let raw: any[] = [];
        try {
            raw = (await client.exchanges().list({ filter })) ?? [];
        } catch {
            // filter may not be supported — fall through to empty
        }
        // always apply manual correlationId check
        const filtered = raw.filter(
            (x: any) => x.exn.a?.correlationId === correlationId
        );
        console.log(
            "[POLL] filter=%s raw=%d filtered=%d want=%d",
            JSON.stringify(filter),
            raw.length,
            filtered.length,
            minCount
        );
        if (filtered.length >= minCount) return filtered;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout waiting for ${minCount} exchanges (filter=${JSON.stringify(filter)} correlationId=${correlationId})`
    );
}

async function createMultisigGroup(
    m1Client: SignifyClient,
    m2Client: SignifyClient,
    groupName: string,
    m1Hab: any,
    m2Hab: any,
    witnessIds: string[]
): Promise<void> {
    // If the group already exists (re-run with fixed brans), skip setup
    try {
        const existing = await m1Client.identifiers().get(groupName);
        console.log("[SETUP] Group %s already exists with prefix=%s, skipping creation", groupName, existing.prefix);
        return;
    } catch {
        // not found — proceed with creation
    }

    // Both members need each other's key states resolved before creating the group
    const m1State = (await m1Client.keyStates().get(m1Hab.prefix))[0];
    const m2State = (await m1Client.keyStates().get(m2Hab.prefix))[0];
    const states = [m1State, m2State];
    const rstates = states;
    const smids = states.map((s: any) => s.i);

    // M1 initiates group
    const icpResult1 = await m1Client.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: m1Hab,
        isith: 2,
        nsith: 2,
        toad: witnessIds.length,
        wits: witnessIds,
        states,
        rstates,
    });
    const op1 = await icpResult1.op();

    const sigers1 = icpResult1.sigs.map((s: string) => new Siger({ qb64: s }));
    const ims1 = d(messagize(icpResult1.serder, sigers1));
    const atc1 = ims1.substring(icpResult1.serder.size);

    await m1Client.exchanges().send(
        "m1",
        "multisig",
        m1Hab,
        "/multisig/icp",
        { gid: icpResult1.serder.pre, smids, rmids: smids },
        { icp: [icpResult1.serder, atc1] },
        [m2Hab.prefix]
    );
    console.log("[SETUP] M1 sent /multisig/icp for group %s", icpResult1.serder.pre);

    // M2 joins
    const msgSaid = await waitAndMarkNotification(m2Client, "/multisig/icp");
    const req = await m2Client.groups().getRequest(msgSaid);
    const icp = req[0].exn.e.icp;

    const m1State2 = (await m2Client.keyStates().get(m1Hab.prefix))[0];
    const m2State2 = (await m2Client.keyStates().get(m2Hab.prefix))[0];

    const icpResult2 = await m2Client.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: m2Hab,
        isith: icp.kt,
        nsith: icp.nt,
        toad: parseInt(icp.bt),
        wits: icp.b,
        states: [m1State2, m2State2],
        rstates: [m1State2, m2State2],
    });
    const op2 = await icpResult2.op();

    const sigers2 = icpResult2.sigs.map((s: string) => new Siger({ qb64: s }));
    const ims2 = d(messagize(icpResult2.serder, sigers2));
    const atc2 = ims2.substring(icpResult2.serder.size);

    await m2Client.exchanges().send(
        "m2",
        "multisig",
        m2Hab,
        "/multisig/icp",
        { gid: icpResult2.serder.pre, smids, rmids: smids },
        { icp: [icpResult2.serder, atc2] },
        [m1Hab.prefix]
    );
    console.log("[SETUP] M2 sent /multisig/icp back to M1");

    await Promise.all([
        waitOperation(m1Client, op1),
        waitOperation(m2Client, op2),
    ]);
    console.log("[SETUP] Group %s created", icpResult1.serder.pre);

    // Add agent end roles — multisig requires /multisig/rpy exchange for each agent EID
    const g1HabM1 = await m1Client.identifiers().get(groupName);
    const members = await m1Client.identifiers().members(groupName);
    const signings: any[] = members["signing"];
    const stamp = signifyDatetime();

    for (const signing of signings) {
        const eid = Object.keys(signing.ends.agent)[0];
        console.log("[SETUP] Adding agent end role for eid=%s", eid);

        // M1 initiates
        const m1Res = await m1Client
            .identifiers()
            .addEndRole(groupName, "agent", eid, stamp);
        const op1r = await m1Res.op();
        const rpy1 = m1Res.serder;
        const sigs1 = m1Res.sigs;
        const state1 = g1HabM1.state;
        const seal1 = ["SealEvent", { i: g1HabM1.prefix, s: state1.ee.s, d: state1.ee.d }];
        const sigers1 = sigs1.map((s: string) => new Siger({ qb64: s }));
        const ims1 = d(messagize(rpy1, sigers1, seal1, undefined, undefined, false));
        await m1Client.exchanges().send(
            "m1", "multisig", m1Hab,
            "/multisig/rpy",
            { gid: g1HabM1.prefix },
            { rpy: [rpy1, ims1.substring(rpy1.size)] },
            [m2Hab.prefix]
        );

        // M2 co-signs
        const msgSaid = await waitAndMarkNotification(m2Client, "/multisig/rpy");
        const req = await m2Client.groups().getRequest(msgSaid);
        const exn = req[0].exn;
        const m2Res = await m2Client
            .identifiers()
            .addEndRole(groupName, exn.e.rpy.a.role, exn.e.rpy.a.eid, exn.e.rpy.dt);
        const op2r = await m2Res.op();
        const rpy2 = m2Res.serder;
        const sigs2 = m2Res.sigs;
        const g1HabM2 = await m2Client.identifiers().get(groupName);
        const state2 = g1HabM2.state;
        const seal2 = ["SealEvent", { i: g1HabM2.prefix, s: state2.ee.s, d: state2.ee.d }];
        const sigers2 = sigs2.map((s: string) => new Siger({ qb64: s }));
        const ims2 = d(messagize(rpy2, sigers2, seal2, undefined, undefined, false));
        await m2Client.exchanges().send(
            "m2", "multisig", m2Hab,
            "/multisig/rpy",
            { gid: g1HabM2.prefix },
            { rpy: [rpy2, ims2.substring(rpy2.size)] },
            [m1Hab.prefix]
        );

        await Promise.all([
            waitOperation(m1Client, op1r),
            waitOperation(m2Client, op2r),
        ]);
        console.log("[SETUP] Agent end role for eid=%s added", eid);
    }
}

// ─── test ─────────────────────────────────────────────────────────────────────

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
        // Fixed brans so re-runs reuse existing KERIA agents instead of creating new ones
        // NOTE: bumped m1 to v2 to get a fresh KERIA agent (old one had broken notifier)
        [m1Client, m2Client, csClient, aliceClient] = await Promise.all([
            getOrCreateClient("wap-e2e-m1-bran-fresh-v2"),
            getOrCreateClient("wap-e2e-m2-bran-fixed-2"),
            getOrCreateClient("wap-e2e-cs-bran-fixed-3"),
            getOrCreateClient("wap-e2e-alice-bran-fixed"),
        ]);

        const witArgs = {
            toad: env.witnessIds.length,
            wits: env.witnessIds,
        };
        await Promise.all([
            getOrCreateIdentifier(m1Client, "m1", witArgs),
            getOrCreateIdentifier(m2Client, "m2", witArgs),
            getOrCreateIdentifier(csClient, "cs", witArgs),
            getOrCreateIdentifier(aliceClient, "alice", witArgs),
        ]);
        [m1Hab, m2Hab, csHab, aliceHab] = await Promise.all([
            m1Client.identifiers().get("m1"),
            m2Client.identifiers().get("m2"),
            csClient.identifiers().get("cs"),
            aliceClient.identifiers().get("alice"),
        ]);
        console.log("[SETUP] Identifiers created: m1=%s m2=%s cs=%s alice=%s",
            m1Hab.prefix, m2Hab.prefix, csHab.prefix, aliceHab.prefix);

        // Exchange OOBIs so members can resolve each other (required for key state query)
        const [m1Oobi, m2Oobi, csOobi, aliceOobi] = (await Promise.all([
            m1Client.oobis().get("m1", "agent").then((r: any) => r.oobis[0]),
            m2Client.oobis().get("m2", "agent").then((r: any) => r.oobis[0]),
            csClient.oobis().get("cs", "agent").then((r: any) => r.oobis[0]),
            aliceClient.oobis().get("alice", "agent").then((r: any) => r.oobis[0]),
        ])).map((o: string) => rewriteOobi(o, env.preset));

        const schemaOobi = `${SCHEMA_BASE_URL}/oobi/${SCHEMA_SAID}`;

        await Promise.all([
            // M1 resolves M2, CS, Alice, schema
            m1Client.oobis().resolve(m2Oobi, "m2").then((op: any) => waitOperation(m1Client, op)),
            m1Client.oobis().resolve(csOobi, "cs").then((op: any) => waitOperation(m1Client, op)),
            m1Client.oobis().resolve(aliceOobi, "alice").then((op: any) => waitOperation(m1Client, op)),
            m1Client.oobis().resolve(schemaOobi, "schema").then((op: any) => waitOperation(m1Client, op)),
            // M2 resolves M1, CS, Alice, schema
            m2Client.oobis().resolve(m1Oobi, "m1").then((op: any) => waitOperation(m2Client, op)),
            m2Client.oobis().resolve(csOobi, "cs").then((op: any) => waitOperation(m2Client, op)),
            m2Client.oobis().resolve(aliceOobi, "alice").then((op: any) => waitOperation(m2Client, op)),
            m2Client.oobis().resolve(schemaOobi, "schema").then((op: any) => waitOperation(m2Client, op)),
            // CS resolves M1, M2, Alice, schema (G1 OOBI resolved after group creation)
            csClient.oobis().resolve(m1Oobi, "m1").then((op: any) => waitOperation(csClient, op)),
            csClient.oobis().resolve(m2Oobi, "m2").then((op: any) => waitOperation(csClient, op)),
            csClient.oobis().resolve(aliceOobi, "alice").then((op: any) => waitOperation(csClient, op)),
            csClient.oobis().resolve(schemaOobi, "schema").then((op: any) => waitOperation(csClient, op)),
        ]);
        console.log("[SETUP] All OOBIs resolved");

        // Create multisig group G1
        await createMultisigGroup(m1Client, m2Client, "G1v2", m1Hab, m2Hab, env.witnessIds);

        g1HabM1 = await m1Client.identifiers().get("G1v2");
        g1HabM2 = await m2Client.identifiers().get("G1v2");
        console.log("[SETUP] G1 prefix=%s", g1HabM1.prefix);

        // CS resolves G1 OOBI from BOTH M1 and M2 views so it learns both agent endpoints
        const g1OobisFromM1 = (await m1Client.oobis().get("G1v2", "agent")).oobis;
        const g1OobisFromM2 = (await m2Client.oobis().get("G1v2", "agent")).oobis;
        console.log("[SETUP] G1 OOBIs from M1: %s", JSON.stringify(g1OobisFromM1));
        console.log("[SETUP] G1 OOBIs from M2: %s", JSON.stringify(g1OobisFromM2));

        const allG1Oobis = [...g1OobisFromM1, ...g1OobisFromM2].map((o: string) =>
            rewriteOobi(o, env.preset));
        for (const g1Oobi of allG1Oobis) {
            const op = await csClient.oobis().resolve(g1Oobi, "G1v2");
            await waitOperation(csClient, op);
            console.log("[SETUP] CS resolved G1 OOBI: %s", g1Oobi);
        }

        // G1 members resolve CS (so ACK exchange can reach CS)
        await Promise.all([
            m1Client.oobis().resolve(csOobi, "cs").then((op: any) => waitOperation(m1Client, op)).catch(() => {}),
            m2Client.oobis().resolve(csOobi, "cs").then((op: any) => waitOperation(m2Client, op)).catch(() => {}),
        ]);

        // Diagnostic: inspect G1's end roles from M1's side
        const g1Members = await m1Client.identifiers().members("G1v2");
        console.log("[SETUP] G1 members (from M1 view):", JSON.stringify(g1Members, null, 2));
        console.log("[SETUP] Current M1 agent EID = %s", m1Client.agent?.pre);
        console.log("[SETUP] Current M2 agent EID = %s", m2Client.agent?.pre);
        console.log("[SETUP] Current CS agent EID = %s", csClient.agent?.pre);

        // Verify mutual contacts — exchange delivery won't work without them
        const csG1Contact = await csClient.contacts().get(g1HabM1.prefix).catch(() => null);
        console.log("[SETUP] CS has G1 as contact: %s (id=%s alias=%s)",
            !!csG1Contact, csG1Contact?.id, csG1Contact?.alias);
        expect(csG1Contact).toBeTruthy();

        const m1CsContact = await m1Client.contacts().get(csHab.prefix).catch(() => null);
        console.log("[SETUP] M1 has CS as contact: %s (id=%s alias=%s)",
            !!m1CsContact, m1CsContact?.id, m1CsContact?.alias);
        expect(m1CsContact).toBeTruthy();

        const m2CsContact = await m2Client.contacts().get(csHab.prefix).catch(() => null);
        console.log("[SETUP] M2 has CS as contact: %s (id=%s alias=%s)",
            !!m2CsContact, m2CsContact?.id, m2CsContact?.alias);
        expect(m2CsContact).toBeTruthy();
    }, 180000);

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

        const m1NoteList = await waitForNotifications(m1Client, "/exn/wap/iss", { timeout: 30000 });
        const m1Note = m1NoteList[0];
        console.log("[TEST] M1 got /exn/wap/iss: notifSaid=%s exchSaid=%s", m1Note.i, m1Note.a.d);

        const m1RequestExn = await m1Client.exchanges().get(m1Note.a.d!);
        const payload = m1RequestExn.exn.a as { n: string; l: any[] };
        const correlationId: string = m1RequestExn.exn.d;
        expect(correlationId).toBe(wapIssSaid);
        console.log("[TEST] correlationId=%s credCount=%d", correlationId, payload.l.length);

        // M1: create VCP registry (don't wait for op — multisig needs M2 co-sign first)
        const regResult = await m1Client.registries().create({
            name: "G1v2",
            registryName: `wap-registry-${nonce}`,
            nonce,
        });
        const m1VcpOp = await regResult.op();
        const vcpIxnSn = parseInt(regResult.serder.ked.s, 16);
        console.log("[TEST] M1 created VCP: ixnSn=%d ixnSaid=%s", vcpIxnSn, regResult.serder.ked.d);

        // M1: send /multisig/vcp to M2
        const vcpEmbed = buildRegistryEmbed(regResult);
        await m1Client.exchanges().send(
            "m1",
            "registry",
            m1Hab,
            "/multisig/vcp",
            { gid: g1Prefix, correlationId },
            vcpEmbed,
            [m2Hab.prefix]
        );
        console.log("[TEST] M1 sent /multisig/vcp correlationId=%s", correlationId);

        // M1: issue each credential, chain anchors — don't wait for each op yet
        let anchor = { sn: vcpIxnSn, d: regResult.serder.ked.d };
        const m1IssOps: any[] = [];
        for (const [i, cred] of payload.l.entries()) {
            const issParams = {
                i: g1Prefix,
                ri: regk,
                s: cred.s,
                a: cred.a,
                ...(cred.u ? { u: cred.u } : {}),
            };
            console.log("[TEST] M1 issuing cred[%d]: schema=%s anchorBase=%d targetSn=%d",
                i, cred.s, anchor.sn, anchor.sn + 1);

            const issResult = await m1Client
                .credentials()
                .issue("G1v2", issParams, anchor);
            m1IssOps.push(issResult.op);
            console.log("[TEST] M1 issued cred[%d]: acdc=%s anc.sn=%d anc.d=%s",
                i, issResult.acdc?.ked?.d, issResult.anc?.sn, issResult.anc?.ked?.d);

            const issEmbed = await buildCredentialEmbed(m1Client, g1HabM1, issResult);
            await m1Client.exchanges().send(
                "m1",
                "multisig",
                m1Hab,
                "/multisig/iss",
                { gid: g1Prefix, correlationId },
                issEmbed,
                [m2Hab.prefix]
            );
            console.log("[TEST] M1 sent /multisig/iss[%d] correlationId=%s", i, correlationId);

            // advance anchor chain exactly as M1 does in issuanceService
            anchor = { sn: issResult.anc.sn, d: issResult.anc.ked.d };
        }

        // M1: send /multisig/exn wrapping /wap/iss/ack
        const [ackExn1, , ackAtc1] = await m1Client
            .exchanges()
            .createExchangeMessage(
                g1HabM1,
                "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {},
                m1RequestExn.exn.i,    // CS AID
                m1RequestExn.exn.dt,   // same dt as /wap/iss → deterministic SAID
                m1RequestExn.exn.d     // prior = /wap/iss SAID
            );
        await m1Client.exchanges().send(
            "m1",
            "multisig",
            m1Hab,
            "/multisig/exn",
            { gid: g1Prefix },
            { exn: [ackExn1, ackAtc1] },
            [m2Hab.prefix]
        );
        console.log("[TEST] M1 sent /multisig/exn (ACK): ackSaid=%s", ackExn1.ked.d);
        await m1Client.notifications().mark(m1Note.i);

        // ── M2 cosigner flow ──────────────────────────────────────────────────
        // KERIA delivers /wap/iss to only ONE group member (M1 in this run, the lead).
        // M2 doesn't receive /exn/wap/iss directly — it gets the data from
        // /multisig/vcp + /multisig/iss exchanges M1 forwards with correlationId.

        // M2 polls for /multisig/vcp and /multisig/iss with this correlationId
        const vcpExchanges = await pollExchanges(
            m2Client,
            { "-r": "/multisig/vcp", "-a-correlationId": correlationId },
            1,
            correlationId
        );
        const issExchanges = (await pollExchanges(
            m2Client,
            { "-r": "/multisig/iss", "-a-correlationId": correlationId },
            payload.l.length,
            correlationId
        )).sort((a: any, b: any) =>
            parseInt(a.exn.e?.anc?.s ?? "0", 16) - parseInt(b.exn.e?.anc?.s ?? "0", 16)
        );

        console.log("[TEST] M2 got vcpExchanges=%d issExchanges=%d", vcpExchanges.length, issExchanges.length);
        expect(vcpExchanges.length).toBe(1);
        expect(issExchanges.length).toBe(payload.l.length);

        // M2: co-sign VCP
        for (const vcpExchange of vcpExchanges) {
            const anc = vcpExchange.exn.e?.anc as { s: string; p: string };
            const targetVcpSn = parseInt(anc.s, 16);
            const vcpAnchor = { sn: targetVcpSn - 1, d: anc.p };
            console.log("[TEST] M2 co-signing VCP: ancBase=%d targetSn=%d ancPrior=%s",
                vcpAnchor.sn, targetVcpSn, vcpAnchor.d);

            const vcpResult = await m2Client.registries().create({
                name: "G1v2",
                registryName: `wap-registry-${nonce}`,
                nonce,
                anchorPoint: vcpAnchor,
            });
            await Promise.all([
                waitOperation(m2Client, await vcpResult.op()),
                waitOperation(m1Client, m1VcpOp),
            ]);
            console.log("[TEST] M2 VCP co-signed: ixnSn=%s", vcpResult.serder.ked.s);
            expect(parseInt(vcpResult.serder.ked.s, 16)).toBe(targetVcpSn);

            const vcpEmbed2 = buildRegistryEmbed(vcpResult);
            await m2Client.exchanges().send(
                "m2",
                "registry",
                m2Hab,
                "/multisig/vcp",
                { gid: g1Prefix, correlationId },
                vcpEmbed2,
                [m1Hab.prefix]
            );
        }

        // M2: co-sign each ISS (sorted by anc.s ascending)
        for (const [i, issExchange] of issExchanges.entries()) {
            const acdc = issExchange.exn.e?.acdc as Record<string, unknown>;
            const iss = issExchange.exn.e?.iss as { ri: string };
            const anc = issExchange.exn.e?.anc as { s: string; p: string };
            const targetIssSn = parseInt(anc.s, 16);
            const issAnchor = { sn: targetIssSn - 1, d: anc.p };

            console.log("[TEST] M2 co-signing ISS[%d/%d]: ancBase=%d targetSn=%d acdc.s=%s",
                i, issExchanges.length - 1, issAnchor.sn, targetIssSn, acdc.s);

            const issResult = await m2Client.credentials().issue("G1v2", {
                i: g1Prefix,
                ri: iss.ri,
                s: acdc.s as string,
                a: acdc.a as Record<string, unknown>,
                ...(acdc.u ? { u: acdc.u as string } : {}),
            }, issAnchor);
            await Promise.all([
                waitOperation(m2Client, issResult.op),
                waitOperation(m1Client, m1IssOps[i]),
            ]);

            console.log("[TEST] M2 ISS[%d] done: acdc.d=%s anc.sn=%d (expected %d)",
                i, issResult.acdc?.ked?.d, issResult.anc?.sn, targetIssSn);
            expect(issResult.anc?.sn).toBe(targetIssSn);

            const issEmbed2 = await buildCredentialEmbed(m2Client, g1HabM2, issResult);
            await m2Client.exchanges().send(
                "m2",
                "multisig",
                m2Hab,
                "/multisig/iss",
                { gid: g1Prefix, correlationId },
                issEmbed2,
                [m1Hab.prefix]
            );
            console.log("[TEST] M2 sent /multisig/iss[%d] correlationId=%s", i, correlationId);
        }

        // M2: send /multisig/exn (ACK) — uses same dt/prior as M1 for deterministic SAID.
        // M2 doesn't have the /wap/iss exchange (KERIA only delivered to M1),
        // so reuse M1's exchange data (sender, dt, SAID).
        const [ackExn2, , ackAtc2] = await m2Client
            .exchanges()
            .createExchangeMessage(
                g1HabM2,
                "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {},
                m1RequestExn.exn.i,
                m1RequestExn.exn.dt,
                m1RequestExn.exn.d
            );
        await m2Client.exchanges().send(
            "m2",
            "multisig",
            m2Hab,
            "/multisig/exn",
            { gid: g1Prefix },
            { exn: [ackExn2, ackAtc2] },
            [m1Hab.prefix]
        );
        console.log("[TEST] M2 sent /multisig/exn (ACK): ackSaid=%s", ackExn2.ked.d);
        expect(ackExn2.ked.d).toBe(ackExn1.ked.d); // same dt → same SAID

        // ── Verify CS receives ACK ────────────────────────────────────────────
        console.log("[TEST] Waiting for CS to receive /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotifications(csClient, "/exn/wap/iss/ack", {
            timeout: 60000,
        });
        const csAckNote = csAckNotes[0];
        console.log("[TEST] CS received ACK: notifId=%s exchSaid=%s", csAckNote.i, csAckNote.a.d);
        expect(csAckNote).toBeDefined();
        expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
    }, 300000);
});
