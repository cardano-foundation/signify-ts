/**
 * Stands in for the other party (VQS) so the wallet's auto-connect can be
 * exercised end to end.
 *
 *   npx tsx examples/integration-scripts/conn-req.ts oobi
 *     creates (or reuses) an AID and prints the line to paste into
 *     keria-config/config.json under "iurls", then restart KERIA.
 *
 *   npx tsx examples/integration-scripts/conn-req.ts list
 *     prints the connection requests received so far, each with the agent end
 *     roles authorised on the group it introduced. Run it at each step of the
 *     group setup: a request must not show up before that list is complete.
 *
 * The bran is kept in .conn-req.json so the AID survives restarts and the OOBI
 * in the config stays valid.
 */
import fs from 'fs';
import path from 'path';
import { randomPasscode, ready, SignifyClient, Tier } from 'signify-ts';

const KERIA_URL = process.env.KERIA_URL ?? 'http://127.0.0.1:3901';
const KERIA_BOOT_URL = process.env.KERIA_BOOT_URL ?? 'http://127.0.0.1:3903';
// what the wallet reaches from inside docker, so the OOBI is resolvable there
const OOBI_HOST = process.env.OOBI_HOST ?? 'http://keria:3902';
const AID_NAME = 'conn-req';
const STATE_FILE = path.join(process.cwd(), '.conn-req.json');
const WITNESSES = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

function loadBran(): string {
    if (fs.existsSync(STATE_FILE)) {
        return JSON.parse(fs.readFileSync(STATE_FILE, 'utf-8')).bran;
    }
    const bran = randomPasscode();
    fs.writeFileSync(STATE_FILE, JSON.stringify({ bran }, null, 2));
    return bran;
}

async function connect(): Promise<SignifyClient> {
    await ready();
    const client = new SignifyClient(
        KERIA_URL,
        loadBran(),
        Tier.low,
        KERIA_BOOT_URL
    );
    try {
        await client.connect();
    } catch {
        await client.boot();
        await client.connect();
    }
    return client;
}

async function waitOp(client: SignifyClient, op: any): Promise<any> {
    return client
        .operations()
        .wait(op, { signal: AbortSignal.timeout(60000) } as any);
}

async function ensureAid(client: SignifyClient): Promise<string> {
    const existing = await client
        .identifiers()
        .get(AID_NAME)
        .catch(() => null);
    if (existing) return existing.prefix;

    const result = await client
        .identifiers()
        .create(AID_NAME, { toad: 3, wits: WITNESSES });
    await waitOp(client, await result.op());
    await client
        .identifiers()
        .addEndRole(AID_NAME, 'agent', client.agent!.pre)
        .then((res) => res.op());
    return (await client.identifiers().get(AID_NAME)).prefix;
}

async function endroles(client: SignifyClient, aid: string): Promise<string[]> {
    const roles = await client
        .oobis()
        .endroles(aid, 'agent')
        .catch(() => []);
    return (roles ?? []).map((role: any) => role.eid);
}

function aidFromOobi(oobi: string): string {
    return new URL(oobi).pathname.split('/oobi/').pop()!.split('/')[0];
}

async function printOobi(): Promise<void> {
    const client = await connect();
    const prefix = await ensureAid(client);
    const oobi = `${OOBI_HOST}/oobi/${prefix}/agent/${
        client.agent!.pre
    }?name=Other%20Party&role=controller`;

    console.log(`AID:   ${prefix}`);
    console.log(`Agent: ${client.agent!.pre}`);
    console.log('');
    console.log(
        'Add this to iurls in keria-config/config.json, then restart keria:'
    );
    console.log(`  "${oobi}"`);
}

async function list(): Promise<void> {
    const client = await connect();
    const prefix = await ensureAid(client);
    const notes = (await client.notifications().list()) as any;
    const requests = (notes.notes ?? []).filter(
        (note: any) => note.a?.r === '/exn/conn/req'
    );

    console.log(`${prefix} has ${requests.length} connection request(s)`);

    for (const note of requests) {
        const exchange = await client.exchanges().get(note.a.d);
        const payload = exchange.exn.a as Record<string, string>;

        console.log('');
        console.log(`from:  ${exchange.exn.i}`);
        console.log(`name:  ${payload.name}`);
        console.log(`oobi:  ${payload.oobi}`);

        const introduced = payload.goobi ?? payload.oobi;
        if (payload.goobi) console.log(`goobi: ${payload.goobi}`);

        await client
            .oobis()
            .resolve(introduced)
            .then((op) => waitOp(client, op))
            .catch(() => undefined);
        console.log(
            `agents authorised on ${
                payload.goobi ? 'the group' : 'the sender'
            }: ${JSON.stringify(
                await endroles(client, aidFromOobi(introduced))
            )}`
        );
    }
}

const mode = process.argv[2] ?? 'oobi';
(mode === 'list' ? list() : printOobi()).catch((error) => {
    console.error(error);
    process.exit(1);
});
