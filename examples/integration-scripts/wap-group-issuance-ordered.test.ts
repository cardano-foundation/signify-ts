/**
 * E2E test: WAP group issuance — ordered sequential phases.
 *
 * Actors: same as wap-group-issuance.test.ts (M1, M2, G1, CS, Alice).
 *
 * Flow (phases run in order; within each phase M1+M2 run concurrently):
 *   1. CS sends /wap/iss to G1
 *   2. M1 gets /exn/wap/iss
 *   3. Phase 1 — VCP:  M1 creates registry + sends /multisig/vcp;
 *                      M2 polls + co-signs + sends back; both ops complete
 *   4. Phase 2 — ISS:  M1 issues credential + sends /multisig/iss;
 *                      M2 polls + co-signs + sends back; both ops complete
 *   5. Phase 3 — ACK:  M1 and M2 both send /multisig/exn (ACK)
 *   6. CS receives /exn/wap/iss/ack
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
import {
    waitForNotifications,
    waitOperation,
} from "./utils/test-util";
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

async function pollExchangesByRoute(
    client: SignifyClient,
    route: string,
    correlationId: string,
    minCount: number,
    timeoutMs = 60000
): Promise<any[]> {
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
        if (attempt % 5 === 0 || filtered.length >= minCount) {
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
        `Timeout: ${minCount} exchanges (route=${route} correlationId=${correlationId})`
    );
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

const clientsPath = path.join(__dirname, "../../examples/.test-clients.json");
const groupPath = path.join(__dirname, "../../examples/.test-group.json");

describe("WAP group issuance E2E (ordered phases)", () => {
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

    it("ordered phases: VCP then ISS then ACK — CS receives /exn/wap/iss/ack", async () => {
        const nonce = randomNonce();
        const g1Prefix = g1HabM1.prefix;
        const alicePrefix = aliceHab.prefix;
        const regk = computeRegk(g1Prefix, nonce);

        // ── CS sends /wap/iss ─────────────────────────────────────────────────
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
                csHab, "/wap/iss",
                { n: nonce, l: [acdcSad] },
                {}, g1Prefix, wapIssDt
            );
        const wapIssSaid = exn.ked.d;
        await csClient.exchanges().sendFromEvents("cs", "iss", exn, sigs, atc, [g1Prefix]);
        console.log("[CS] sent /wap/iss: said=%s", wapIssSaid);

        // ── M1 waits for /exn/wap/iss ─────────────────────────────────────────
        const m1NoteList = await waitForNotifications(m1Client, "/exn/wap/iss", { timeout: 30000 });
        const m1Note = m1NoteList[0];
        const m1RequestExn = await m1Client.exchanges().get(m1Note.a.d!);
        const payload = m1RequestExn.exn.a as { n: string; l: any[] };
        const correlationId: string = m1RequestExn.exn.d;
        expect(correlationId).toBe(wapIssSaid);
        console.log("[M1] got /exn/wap/iss correlationId=%s creds=%d", correlationId, payload.l.length);

        // Shared across phases
        let vcpIxnSn = 0;
        let vcpIxnSaid = "";

        // ── Phase 1: VCP — M1 and M2 run concurrently ────────────────────────
        console.log("[TEST] Phase 1: VCP");

        await Promise.all([
            // M1: create registry, send /multisig/vcp, wait for op
            (async () => {
                const regResult = await m1Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce}`,
                    nonce,
                });
                const m1VcpOp = await regResult.op();
                vcpIxnSn = parseInt(regResult.serder.ked.s, 16);
                vcpIxnSaid = regResult.serder.ked.d;
                console.log("[M1] created VCP: ixnSn=%d ixnSaid=%s", vcpIxnSn, vcpIxnSaid);

                const vcpEmbed = buildRegistryEmbed(regResult);
                await m1Client.exchanges().send(
                    "m1", "registry", m1Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId },
                    vcpEmbed, [m2Hab.prefix]
                );
                console.log("[M1] sent /multisig/vcp");

                console.log("[M1] awaiting VCP op...");
                await waitOperation(m1Client, m1VcpOp);
                console.log("[M1] VCP op complete");
            })(),

            // M2: poll for /multisig/vcp, co-sign, send back, wait for op
            (async () => {
                const vcpExchanges = await pollExchangesByRoute(
                    m2Client, "/multisig/vcp", correlationId, 1
                );
                const vcpExchange = vcpExchanges[0];
                const vcpAncFull = vcpExchange.exn.e?.anc as { s: string; p: string };
                const vcpTargetSn = parseInt(vcpAncFull.s, 16);
                const vcpAnchor = { sn: vcpTargetSn - 1, d: vcpAncFull.p };
                console.log("[M2] co-signing VCP: targetSn=%d ancPrior=%s", vcpTargetSn, vcpAnchor.d);

                const m2VcpResult = await m2Client.registries().create({
                    name: "G1v2",
                    registryName: `wap-registry-${nonce}`,
                    nonce,
                    anchorPoint: vcpAnchor,
                });
                const m2VcpOp = await m2VcpResult.op();

                const vcpEmbed2 = buildRegistryEmbed(m2VcpResult);
                await m2Client.exchanges().send(
                    "m2", "registry", m2Hab, "/multisig/vcp",
                    { gid: g1Prefix, correlationId },
                    vcpEmbed2, [m1Hab.prefix]
                );
                console.log("[M2] sent /multisig/vcp back");

                await waitOperation(m2Client, m2VcpOp);
                console.log("[M2] VCP op complete");
            })(),
        ]);

        console.log("[TEST] Phase 1 done — registry committed");

        // ── Phase 2: ISS — M1 and M2 run concurrently ────────────────────────
        // Both start at the same time: M1 issues and starts polling its op immediately;
        // M2 polls for the exchange. Because M1 is already waiting for its op when M2's
        // co-sign arrives, KERIA's counselor runs and marks M1's op done without contention.
        console.log("[TEST] Phase 2: ISS");

        await Promise.all([
            // M1: issue credential, send /multisig/iss, wait for op
            (async () => {
                for (const [i, cred] of payload.l.entries()) {
                    const issParams = {
                        i: g1Prefix,
                        ri: regk,
                        s: cred.s,
                        a: cred.a,
                        ...(cred.u ? { u: cred.u } : {}),
                    };
                    const anchor = { sn: vcpIxnSn, d: vcpIxnSaid };
                    console.log("[M1] issuing cred[%d] anchorSn=%d", i, anchor.sn);

                    const issResult = await m1Client.credentials().issue("G1v2", issParams, anchor);
                    console.log("[M1] cred[%d] issued: anc.sn=%d", i, issResult.anc?.sn);

                    const issEmbed = await buildCredentialEmbed(m1Client, g1HabM1, issResult);
                    await m1Client.exchanges().send(
                        "m1", "multisig", m1Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId },
                        issEmbed, [m2Hab.prefix]
                    );
                    console.log("[M1] sent /multisig/iss[%d]", i);

                    // M1 polls its ISS op here. M2 runs concurrently and will co-sign
                    // this exchange while M1 is already polling — avoids KERIA lock contention.
                    console.log("[M1] awaiting iss[%d] op...", i);
                    await waitOperation(m1Client, issResult.op);
                    console.log("[M1] iss[%d] op complete", i);

                    vcpIxnSn = issResult.anc.sn;
                    vcpIxnSaid = issResult.anc.ked.d;
                }
            })(),

            // M2: poll for /multisig/iss, co-sign each, send back, wait for op
            (async () => {
                const issExchanges = (await pollExchangesByRoute(
                    m2Client, "/multisig/iss", correlationId, payload.l.length
                )).sort((a: any, bx: any) =>
                    parseInt(a.exn.e?.anc?.s ?? "0", 16) - parseInt(bx.exn.e?.anc?.s ?? "0", 16)
                );
                console.log("[M2] got %d /multisig/iss exchange(s)", issExchanges.length);

                for (const [i, issExchange] of issExchanges.entries()) {
                    const acdc = issExchange.exn.e?.acdc as Record<string, unknown>;
                    const iss = issExchange.exn.e?.iss as { ri: string };
                    const issAncFull = issExchange.exn.e?.anc as { s: string; p: string };
                    const issTargetSn = parseInt(issAncFull.s, 16);
                    const issAnchor = { sn: issTargetSn - 1, d: issAncFull.p };
                    console.log("[M2] co-signing ISS[%d]: targetSn=%d", i, issTargetSn);

                    const m2IssResult = await m2Client.credentials().issue("G1v2", {
                        i: g1Prefix,
                        ri: iss.ri,
                        s: acdc.s as string,
                        a: acdc.a as Record<string, unknown>,
                        ...(acdc.u ? { u: acdc.u as string } : {}),
                    }, issAnchor);

                    const issEmbed2 = await buildCredentialEmbed(m2Client, g1HabM2, m2IssResult);
                    await m2Client.exchanges().send(
                        "m2", "multisig", m2Hab, "/multisig/iss",
                        { gid: g1Prefix, correlationId },
                        issEmbed2, [m1Hab.prefix]
                    );
                    console.log("[M2] sent /multisig/iss[%d] back", i);

                    await waitOperation(m2Client, m2IssResult.op);
                    console.log("[M2] iss[%d] op complete", i);
                }
            })(),
        ]);

        console.log("[TEST] Phase 2 done — credentials issued");

        // Give KERIA a moment to finish post-op finalization for both agents before
        // Phase 3. Without this, the member whose ISS op just completed (M2) will
        // block on the next HTTP call to KERIA while it holds an internal lock.
        await new Promise((r) => setTimeout(r, 3000));

        // ── Phase 3: ACK ─────────────────────────────────────────────────────
        // Both members sign the ACK with the same params (same dt → same SAID).
        // M1 submits with both sigs in one call: KERIA sees 2/2 threshold met
        // immediately, stores exchange in exns, wapacks entry added.
        // WapackSender on M1's agent: complete()=true, lead()=true (M1 has index 0),
        // delivers ACK + artifacts to CS.
        console.log("[TEST] Phase 3: ACK");

        const [[ackExn, ackSigs1], [, ackSigs2]] = await Promise.all([
            m1Client.exchanges().createExchangeMessage(
                g1HabM1, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {}, m1RequestExn.exn.i, m1RequestExn.exn.dt, m1RequestExn.exn.d
            ),
            m2Client.exchanges().createExchangeMessage(
                g1HabM2, "/wap/iss/ack",
                { r: "/wap/iss/ack", p: m1RequestExn.exn.d },
                {}, m1RequestExn.exn.i, m1RequestExn.exn.dt, m1RequestExn.exn.d
            ),
        ]);

        await m1Client.exchanges().sendFromEvents(
            "G1v2", "wap",
            ackExn,
            [...ackSigs1, ...ackSigs2],
            "",
            [csHab.prefix]
        );
        console.log("[M1] submitted ACK with both sigs: said=%s", ackExn.ked.d);
        await m1Client.notifications().mark(m1Note.i);

        // ── CS receives /exn/wap/iss/ack ─────────────────────────────────────
        console.log("[TEST] Waiting for CS to receive /exn/wap/iss/ack...");
        const csAckNotes = await waitForNotifications(csClient, "/exn/wap/iss/ack", {
            timeout: 60000,
        });
        const csAckNote = csAckNotes[0];
        console.log("[CS] received ACK: notifId=%s exchSaid=%s", csAckNote?.i, csAckNote?.a?.d);
        expect(csAckNote).toBeDefined();
        expect(csAckNote.a.r).toBe("/exn/wap/iss/ack");
    }, 300000);
});
