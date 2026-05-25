import {
    SignifyClient,
    Tier,
    ready,
} from 'signify-ts';
import { resolveEnvironment } from './resolve-env';
import { waitOperation } from './test-util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SCHEMA_SAID = 'EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb';
const SCHEMA_BASE_URL = process.env.SCHEMA_BASE_URL ?? 'http://cred-issuance:3001';

const env = resolveEnvironment();
const clientsPath = path.join(__dirname, '../../.test-clients.json');
const groupPath = path.join(__dirname, '../../.test-group.json');
const contactsOutputPath = path.join(__dirname, '../../.test-contacts.json');

function rewriteOobi(oobi: string): string {
    if (env.preset !== 'local') return oobi;
    return oobi
        .replace(/http:\/\/keria:/g, 'http://127.0.0.1:')
        .replace(/http:\/\/witness-demo:/g, 'http://127.0.0.1:');
}

async function getClientFromFile(name: string): Promise<SignifyClient> {
    const clientsData = JSON.parse(fs.readFileSync(clientsPath, 'utf-8'));
    const data = clientsData[name];
    if (!data) throw new Error(`Client ${name} not found in .test-clients.json`);

    await ready();
    const client = new SignifyClient(env.url, data.bran, Tier.low, env.bootUrl);
    await client.connect();
    return client;
}

async function main() {
    console.log('Creating contacts between clients...\n');

    const [m1Client, m2Client, csClient, holderClient] = await Promise.all([
        getClientFromFile('m1'),
        getClientFromFile('m2'),
        getClientFromFile('cs'),
        getClientFromFile('holder'),
    ]);

    const [m1Hab, m2Hab, csHab, holderHab] = await Promise.all([
        m1Client.identifiers().get('m1'),
        m2Client.identifiers().get('m2'),
        csClient.identifiers().get('cs'),
        holderClient.identifiers().get('holder'),
    ]);

    console.log(`M1: ${m1Hab.prefix}`);
    console.log(`M2: ${m2Hab.prefix}`);
    console.log(`CS: ${csHab.prefix}`);
    console.log(`Holder: ${holderHab.prefix}`);

    const [m1Oobi, m2Oobi, csOobi, holderOobi] = (await Promise.all([
        m1Client.oobis().get('m1', 'agent').then((r: any) => r.oobis[0]),
        m2Client.oobis().get('m2', 'agent').then((r: any) => r.oobis[0]),
        csClient.oobis().get('cs', 'agent').then((r: any) => r.oobis[0]),
        holderClient.oobis().get('holder', 'agent').then((r: any) => r.oobis[0]),
    ])).map((o: string) => rewriteOobi(o));

    const groupData = JSON.parse(fs.readFileSync(groupPath, 'utf-8'));
    const schemaOobi = `${SCHEMA_BASE_URL}/oobi/${SCHEMA_SAID}`;

    console.log('\nResolving OOBIs...');

    await Promise.all([
        m1Client.oobis().resolve(m2Oobi, 'm2').then((op: any) => waitOperation(m1Client, op)),
        m1Client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m1Client, op)),
        m1Client.oobis().resolve(holderOobi, 'holder').then((op: any) => waitOperation(m1Client, op)),
        m1Client.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(m1Client, op)),
        m2Client.oobis().resolve(m1Oobi, 'm1').then((op: any) => waitOperation(m2Client, op)),
        m2Client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m2Client, op)),
        m2Client.oobis().resolve(holderOobi, 'holder').then((op: any) => waitOperation(m2Client, op)),
        m2Client.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(m2Client, op)),
        csClient.oobis().resolve(m1Oobi, 'm1').then((op: any) => waitOperation(csClient, op)),
        csClient.oobis().resolve(m2Oobi, 'm2').then((op: any) => waitOperation(csClient, op)),
        csClient.oobis().resolve(holderOobi, 'holder').then((op: any) => waitOperation(csClient, op)),
        csClient.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(csClient, op)),
    ]);
    console.log('Basic OOBIs resolved');

    // Resolve G1 OOBI ONLY via M1's agent endpoint.
    // KERIA last-write-wins: if we also resolved via M2's agent, /wap/iss would go to M2.
    // oobis().get("G1v2", "agent") returns the last-registered agent (usually M2), so
    // we construct M1's OOBI explicitly.
    const m1AgentEid = m1Client.agent!.pre;
    const keriaBase = m1Oobi.split('/oobi/')[0];
    const g1OobiViaM1 = `${keriaBase}/oobi/${groupData.prefix}/agent/${m1AgentEid}`;
    console.log(`\nResolving G1 OOBI via M1 agent: ${g1OobiViaM1}`);
    try {
        const op = await csClient.oobis().resolve(g1OobiViaM1, 'G1v2');
        await Promise.race([
            waitOperation(csClient, op),
            new Promise<void>((_, rej) =>
                setTimeout(() => rej(new Error('oobi waitOp timeout')), 30000)
            ),
        ]);
        console.log('CS resolved G1 OOBI (M1 agent endpoint)');
    } catch (err: any) {
        console.log(`CS G1 OOBI warn: ${err?.message}`);
    }

    await Promise.all([
        m1Client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m1Client, op)).catch(() => {}),
        m2Client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m2Client, op)).catch(() => {}),
    ]);
    console.log('M1/M2 resolved CS OOBI');

    const contactsInfo = {
        m1Contacts: await listContacts(m1Client),
        m2Contacts: await listContacts(m2Client),
        csContacts: await listContacts(csClient),
        holderContacts: await listContacts(holderClient),
    };

    fs.writeFileSync(contactsOutputPath, JSON.stringify(contactsInfo, null, 2));
    console.log(`\nContacts written to ${contactsOutputPath}`);
}

async function listContacts(client: SignifyClient): Promise<Record<string, any>> {
    const contacts = await client.contacts().list();
    const result: Record<string, any> = {};
    for (const c of contacts) {
        result[c.alias] = { id: c.id, alias: c.alias };
    }
    return result;
}

main().catch(console.error);