import {
    SignifyClient,
    Tier,
    ready,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import fs from 'fs';
import path from 'path';

const clientsPath = path.join(__dirname, '../../examples/.test-clients.json');
const contactsPath = path.join(__dirname, '../../examples/.test-contacts.json');

async function getClientFromFile(name: string): Promise<SignifyClient> {
    const clientsData = JSON.parse(fs.readFileSync(clientsPath, 'utf-8'));
    const data = clientsData[name];
    if (!data) throw new Error(`Client ${name} not found`);

    await ready();
    const env = resolveEnvironment();
    const client = new SignifyClient(env.url, data.bran, Tier.low, env.bootUrl);
    await client.connect();
    return client;
}

describe('Contact verification', () => {
    it('should have created contacts between all participants', async () => {
        const clients = JSON.parse(fs.readFileSync(clientsPath, 'utf-8'));
        const contactsData = JSON.parse(fs.readFileSync(contactsPath, 'utf-8'));

        console.log('\n=== Contact Verification ===');
        console.log('\nClients:', JSON.stringify(clients, null, 2));
        console.log('\nContacts:', JSON.stringify(contactsData, null, 2));

        const [m1Client, m2Client, csClient, holderClient] = await Promise.all([
            getClientFromFile('m1'),
            getClientFromFile('m2'),
            getClientFromFile('cs'),
            getClientFromFile('holder'),
        ]);

        const m1Hab = await m1Client.identifiers().get('m1');
        const m2Hab = await m2Client.identifiers().get('m2');
        const csHab = await csClient.identifiers().get('cs');
        const holderHab = await holderClient.identifiers().get('holder');

        console.log('\n--- Identifiers ---');
        console.log(`m1: ${m1Hab.prefix}`);
        console.log(`m2: ${m2Hab.prefix}`);
        console.log(`cs: ${csHab.prefix}`);
        console.log(`holder: ${holderHab.prefix}`);

        console.log('\n--- Contacts from M1 ---');
        const m1Contacts = await m1Client.contacts().list();
        console.log(`Count: ${m1Contacts.length}`);
        for (const c of m1Contacts) {
            console.log(`  ${c.alias}: ${c.id}`);
        }

        console.log('\n--- Contacts from M2 ---');
        const m2Contacts = await m2Client.contacts().list();
        console.log(`Count: ${m2Contacts.length}`);
        for (const c of m2Contacts) {
            console.log(`  ${c.alias}: ${c.id}`);
        }

        console.log('\n--- Contacts from CS ---');
        const csContacts = await csClient.contacts().list();
        console.log(`Count: ${csContacts.length}`);
        for (const c of csContacts) {
            console.log(`  ${c.alias}: ${c.id}`);
        }

        console.log('\n--- Contacts from Holder ---');
        const holderContacts = await holderClient.contacts().list();
        console.log(`Count: ${holderContacts.length}`);
        for (const c of holderContacts) {
            console.log(`  ${c.alias}: ${c.id}`);
        }

        console.log('\n--- Group Info ---');
        const groupPath = path.join(__dirname, '../../examples/.test-group.json');
        if (fs.existsSync(groupPath)) {
            const groupData = JSON.parse(fs.readFileSync(groupPath, 'utf-8'));
            console.log(`Group name: ${groupData.name}`);
            console.log(`Group prefix: ${groupData.prefix}`);
        }

        expect(m1Contacts.length).toBeGreaterThan(0);
        expect(m2Contacts.length).toBeGreaterThan(0);
        expect(csContacts.length).toBeGreaterThan(0);
        expect(holderContacts.length).toBeGreaterThan(0);
    });
});