import signify, { SignifyClient } from 'signify-ts';
import {
    assertOperations,
    getEndRoles,
    getOrCreateClient,
    getOrCreateContact,
    getOrCreateIdentifier,
    waitOperation,
} from './utils/test-util';

let client1: SignifyClient;
let client2: SignifyClient;

const INDEXER_LOC_SCHEME = { url: 'http://indexer.example.com', scheme: 'http' };

let indexerAid: string;
let agentOobi: string;

beforeAll(async () => {
    await signify.ready();
    [client1, client2] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
});

afterAll(async () => {
    await assertOperations(client1, client2);
});

describe('locschemes-by-eid', () => {
    test('user1: create AID with indexer end role and loc scheme', async () => {
        const aidName = 'indexer-node';

        const createResult = await client1.identifiers().create(aidName);
        await waitOperation(client1, await createResult.op());

        const hab = await client1.identifiers().get(aidName);
        indexerAid = hab.prefix;

        const roles = await getEndRoles(client1, aidName);

        if (!roles.some((r: any) => r.role === 'agent')) {
            const agentResult = await client1
                .identifiers()
                .addEndRole(aidName, 'agent', client1.agent!.pre);
            await waitOperation(client1, await agentResult.op());
        }

        if (!roles.some((r: any) => r.role === 'indexer')) {
            const endResult = await client1
                .identifiers()
                .addEndRole(aidName, 'indexer', indexerAid);
            await waitOperation(client1, await endResult.op());

            const locRes = await client1
                .identifiers()
                .addLocScheme(aidName, INDEXER_LOC_SCHEME);
            await waitOperation(client1, await locRes.op());
        }

        const oobi = await client1.oobis().get(aidName);
        agentOobi = oobi.oobis[0];
    });

    test('resolver: create AID', async () => {
        const [resolverAid] = await getOrCreateIdentifier(client2, 'resolver');
        expect(resolverAid).toBeDefined();
    });

    test('resolver: resolve user1 agent OOBI', async () => {
        const contactId = await getOrCreateContact(
            client2,
            'indexer-node',
            agentOobi
        );
        expect(contactId).toBeDefined();
    });

    test('resolver: fetch loc schemes by indexer EID', async () => {
        const oobiBase = agentOobi.split('/oobi/')[0];
        await waitOperation(client2, await client2.oobis().resolve(`${oobiBase}/oobi/${indexerAid}/indexer/${indexerAid}`));
        const roles = await client2.oobis().endroles(indexerAid, 'indexer');
        const indexerRole = roles.find((r: any) => r.role === 'indexer');
        expect(indexerRole).toBeDefined();

        const locSchemes = await client2.oobis().locschemes(indexerRole.eid);
        expect(locSchemes).toEqual(
            expect.arrayContaining([
                expect.objectContaining(INDEXER_LOC_SCHEME),
            ])
        );
    });
});
