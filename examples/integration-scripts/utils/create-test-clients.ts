import signify, { SignifyClient, Tier, ready, randomPasscode } from 'signify-ts';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WAN = 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha';
const WIL = 'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM';
const WES = 'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX';

const env = {
    preset: 'local' as const,
    url: 'http://127.0.0.1:3901',
    bootUrl: 'http://127.0.0.1:3903',
    witnessIds: [WAN, WIL, WES],
};

const OUTPUT_FILE = path.join(__dirname, '../../.test-clients.json');

async function createClient(): Promise<SignifyClient> {
    await ready();
    const bran = randomPasscode().padEnd(21, '_');
    const client = new SignifyClient(env.url, bran, Tier.low, env.bootUrl);
    try {
        await client.connect();
    } catch {
        const res = await client.boot();
        if (!res.ok) throw new Error('Boot failed');
        await client.connect();
    }
    return client;
}

async function hasEndRole(client: SignifyClient, alias: string, role: string, eid: string): Promise<boolean> {
    try {
        const response: Response = await client.fetch(`/identifiers/${alias}/endroles/${role}`, 'GET', null);
        if (!response.ok) return false;
        const list = await response.json();
        return list.some((i: any) => i.role === role && i.eid === eid);
    } catch {
        return false;
    }
}

async function waitOperation<T = any>(client: SignifyClient, op: any): Promise<any> {
    op = await client.operations().wait(op, { signal: AbortSignal.timeout(30000) });
    await client.operations().delete(op.name);
    return op;
}

async function main() {
    console.log('Creating 4 test clients...\n');

    const clients = await Promise.all([
        createClient(),
        createClient(),
        createClient(),
        createClient(),
    ]);

    const witArgs = {
        toad: env.witnessIds.length,
        wits: env.witnessIds,
    };

    const names = ['m1', 'm2', 'cs', 'holder'];
    const identifiers: any = {};

    for (let i = 0; i < clients.length; i++) {
        const client = clients[i];
        const name = names[i];
        console.log(`Creating identifier ${name}...`);

        let id: string;
        try {
            const ident = await client.identifiers().get(name);
            id = ident.prefix;
            console.log(`  ${name} already exists: prefix=${id}`);
        } catch {
            const result = await client.identifiers().create(name, witArgs);
            const op = await waitOperation(client, await result.op());
            id = op.response.i;
            console.log(`  ${name} created: prefix=${id}`);
        }

        const eid = client.agent?.pre!;
        if (!(await hasEndRole(client, name, 'agent', eid))) {
            const result = await client.identifiers().addEndRole(name, 'agent', eid);
            await waitOperation(client, await result.op());
            console.log(`  ${name} added agent endRole: eid=${eid}`);
        } else {
            console.log(`  ${name} agent endRole already exists: eid=${eid}`);
        }

        const oobi = await client.oobis().get(name, 'agent');
        identifiers[name] = {
            bran: client.bran,
            controller: client.controller.pre,
            agent: client.agent?.pre,
            prefix: id,
            oobi: oobi.oobis[0],
        };
        console.log(`  ${name} OOBI: ${oobi.oobis[0]}\n`);
    }

    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(identifiers, null, 2));
    console.log(`Clients written to ${OUTPUT_FILE}`);
    console.log('\nClient summary:');
    for (const [name, data] of Object.entries(identifiers)) {
        console.log(`  ${name}: ${(data as any).prefix}`);
    }
}

main().catch(console.error);