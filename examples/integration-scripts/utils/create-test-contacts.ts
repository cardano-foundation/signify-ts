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

interface MemberInfo {
    name: string;
    client: SignifyClient;
    aid: string;
    oobi: string;
}

async function main() {
    console.log('Creating contacts between clients...\n');

    const clientsData = JSON.parse(fs.readFileSync(clientsPath, 'utf-8')) as any;
    const memberNames: string[] = clientsData._meta?.memberNames ?? ['m1', 'm2'];
    const groupData = JSON.parse(fs.readFileSync(groupPath, 'utf-8'));

    const [csClient, holderClient] = await Promise.all([
        getClientFromFile('cs'),
        getClientFromFile('holder'),
    ]);
    const memberClients = await Promise.all(memberNames.map((n) => getClientFromFile(n)));

    const [csHab, holderHab, ...memberHabs] = await Promise.all([
        csClient.identifiers().get('cs'),
        holderClient.identifiers().get('holder'),
        ...memberClients.map((c, i) => c.identifiers().get(memberNames[i])),
    ]);

    console.log(`CS: ${csHab.prefix}`);
    console.log(`Holder: ${holderHab.prefix}`);
    for (let i = 0; i < memberNames.length; i++) {
        console.log(`${memberNames[i]}: ${memberHabs[i].prefix}`);
    }

    const members: MemberInfo[] = await Promise.all(
        memberClients.map(async (client, i) => ({
            name: memberNames[i],
            client,
            aid: memberHabs[i].prefix,
            oobi: rewriteOobi((await client.oobis().get(memberNames[i], 'agent')).oobis[0]),
        }))
    );

    const csOobi = rewriteOobi((await csClient.oobis().get('cs', 'agent')).oobis[0]);
    const holderOobi = rewriteOobi((await holderClient.oobis().get('holder', 'agent')).oobis[0]);
    const schemaOobi = `${SCHEMA_BASE_URL}/oobi/${SCHEMA_SAID}`;

    console.log('\nResolving member <-> external OOBIs...');

    // Every member resolves cs, holder and the schema. cs and holder resolve
    // every member.
    const resolutions: Promise<unknown>[] = [];

    for (const m of members) {
        resolutions.push(
            m.client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m.client, op)),
            m.client.oobis().resolve(holderOobi, 'holder').then((op: any) => waitOperation(m.client, op)),
            m.client.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(m.client, op)),
        );
        resolutions.push(
            csClient.oobis().resolve(m.oobi, m.name).then((op: any) => waitOperation(csClient, op)),
        );
    }
    resolutions.push(
        csClient.oobis().resolve(holderOobi, 'holder').then((op: any) => waitOperation(csClient, op)),
        csClient.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(csClient, op)),
        // Holder also needs the schema cached locally so that after the IPEX
        // admit, its KERIA can verify the ACDC against the schema.
        holderClient.oobis().resolve(schemaOobi, 'schema').then((op: any) => waitOperation(holderClient, op)),
    );

    await Promise.all(resolutions);
    console.log('External OOBIs resolved');

    // CS and holder both need the group AID's `agent` role endpoints for
    // EVERY member, so that KERIA's WitnessInquisitor (used by the WAP iss
    // exchange routing on CS side, and by the IPEX admit's TEL query on the
    // holder side) can reach any member-agent. ends DB key is
    // (cid, role, eid) so all entries coexist under Roles.agent.
    const keriaBase = members[0].oobi.split('/oobi/')[0];
    const groupOobis = members.map((m) => ({
        memberName: m.name,
        url: `${keriaBase}/oobi/${groupData.prefix}/agent/${m.client.agent!.pre}`,
    }));

    console.log(`\nResolving group OOBIs (${groupOobis.length}) on CS and holder`);
    const groupResolutions: Promise<void>[] = [];

    for (const g of groupOobis) {
        groupResolutions.push(
            (async () => {
                try {
                    const op = await csClient.oobis().resolve(g.url, groupData.name);
                    await Promise.race([
                        waitOperation(csClient, op),
                        new Promise<void>((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000)),
                    ]);
                    console.log(`CS resolved group OOBI via ${g.memberName} agent`);
                } catch (err: any) {
                    console.log(`CS group via ${g.memberName} warn: ${err?.message}`);
                }
            })(),
            (async () => {
                try {
                    const op = await holderClient.oobis().resolve(g.url, groupData.name);
                    await Promise.race([
                        waitOperation(holderClient, op),
                        new Promise<void>((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000)),
                    ]);
                    console.log(`Holder resolved group OOBI via ${g.memberName} agent`);
                } catch (err: any) {
                    console.log(`Holder group via ${g.memberName} warn: ${err?.message}`);
                }
            })(),
        );
    }

    await Promise.all(groupResolutions);

    // Members resolve CS once more (they may need the contact for the WAP iss
    // sender lookup). Tolerant of duplicates.
    await Promise.all(
        members.map((m) =>
            m.client.oobis().resolve(csOobi, 'cs').then((op: any) => waitOperation(m.client, op)).catch(() => {})
        )
    );
    console.log('Members re-confirmed CS contact');

    const contactsInfo: Record<string, Record<string, any>> = {};
    contactsInfo.csContacts = await listContacts(csClient);
    contactsInfo.holderContacts = await listContacts(holderClient);
    for (const m of members) {
        contactsInfo[`${m.name}Contacts`] = await listContacts(m.client);
    }

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
