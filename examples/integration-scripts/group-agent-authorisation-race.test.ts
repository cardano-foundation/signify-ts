import assert from 'assert';
import signify, { SignifyClient } from 'signify-ts';
import {
    getOrCreateClient,
    getOrCreateIdentifier,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util';
import {
    addEndRoleMultisig,
    startMultisigIncept,
    acceptMultisigIncept,
} from './utils/multisig-utils';
import { step } from './utils/test-step';

// The other side freezes the group's agent end roles as its controllers when it
// resolves the OOBI, so a wallet must not send anything before they are all
// there. These walk a group through the authorisation and read the end roles at
// each point, and measure how long the group is exposed.

const WITNESSES = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

let client1: SignifyClient, client2: SignifyClient, aliceClient: SignifyClient;

function log(stage: string, message: string, value?: unknown) {
    const stamp = new Date().toISOString();
    if (value === undefined) {
        console.log(`[${stamp}] [${stage}] ${message}`);
        return;
    }
    console.log(
        `[${stamp}] [${stage}] ${message} ${JSON.stringify(value, null, 2)}`
    );
}

// mirrors ConnectionService.agentsAuthorised
async function walletGateSaysReady(
    client: SignifyClient,
    stage: string,
    groupPrefix: string
): Promise<boolean> {
    const roles = await client.oobis().endroles(groupPrefix, 'agent');
    log(stage, 'raw endroles payload', roles);

    const authorised = new Set((roles ?? []).map((role: any) => role.eid));
    const members = await client.identifiers().members(groupPrefix);
    log(stage, 'members and the agent each one runs', {
        count: members.signing.length,
        agents: members.signing.map(
            (member: any) => Object.keys(member.ends?.agent ?? {})[0]
        ),
        authorised: [...authorised],
    });

    const ready = members.signing.every((member: any) =>
        Object.keys(member.ends?.agent ?? {}).some((eid: string) =>
            authorised.has(eid)
        )
    );
    log(stage, `gate: ${ready ? 'READY, send it' : 'NOT READY, hold it back'}`);
    return ready;
}

async function inceptGroup(
    groupName: string,
    member1: string,
    member2: string
): Promise<{ op1: any; op2: any }> {
    const op1 = await startMultisigIncept(client1, {
        groupName,
        localMemberName: member1,
        participants: [
            (await client1.identifiers().get(member1)).prefix,
            (await client2.identifiers().get(member2)).prefix,
        ],
        isith: 2,
        nsith: 2,
        toad: 3,
        wits: WITNESSES,
    });

    const notes = await waitForNotifications(client2, '/multisig/icp');
    await Promise.all(
        notes.map((note) => client2.notifications().mark(note.i))
    );
    const msgSaid = notes[notes.length - 1].a.d;
    assert(msgSaid, 'msgSaid not defined');

    const op2 = await acceptMultisigIncept(client2, {
        localMemberName: member2,
        groupName,
        msgSaid,
    });

    return { op1, op2 };
}

beforeAll(async () => {
    await signify.ready();
    [client1, client2, aliceClient] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
    log('setup', 'agents', {
        member1: client1.agent!.pre,
        member2: client2.agent!.pre,
        alice: aliceClient.agent!.pre,
    });

    // a group AID is derived from its inception event, so the two tests need
    // different members or the second one collides with the first
    for (const [name1, name2] of [
        ['race-member1', 'race-member2'],
        ['away-member1', 'away-member2'],
    ]) {
        await Promise.all([
            getOrCreateIdentifier(client1, name1),
            getOrCreateIdentifier(client2, name2),
        ]);

        const [oobi1, oobi2] = await Promise.all([
            client1.oobis().get(name1, 'agent'),
            client2.oobis().get(name2, 'agent'),
        ]);
        await Promise.all([
            resolveOobi(client1, oobi2.oobis[0], name2),
            resolveOobi(client2, oobi1.oobis[0], name1),
        ]);
    }

    await getOrCreateIdentifier(aliceClient, 'race-alice');
});

afterAll(async () => {
    for (const client of [client1, client2, aliceClient]) {
        const operations = await client.operations().list();
        for (const operation of operations) {
            await client.operations().delete(operation.name);
        }
    }
});

test('the group is exposed until every member has co-signed the end roles', async () => {
    const groupName = 'agent-auth-race';
    const expected = [client1.agent!.pre, client2.agent!.pre].sort();
    let groupAid = '';
    let proposeOps: any[] = [];
    let stamp = '';

    await step('Incept a 2-of-2 group', async () => {
        const { op1, op2 } = await inceptGroup(
            groupName,
            'race-member1',
            'race-member2'
        );
        await Promise.all([
            waitOperation(client1, op1),
            waitOperation(client2, op2),
        ]);
        groupAid = (await client1.identifiers().get(groupName)).prefix;
        log('incepted', 'group', groupAid);
    });

    await step('Right after inception there are no end roles', async () => {
        expect(await client1.oobis().endroles(groupAid, 'agent')).toHaveLength(
            0
        );
        expect(await walletGateSaysReady(client1, 'after icp', groupAid)).toBe(
            false
        );
    });

    await step('One member proposing is not enough on a 2-of-2', async () => {
        const member1 = await client1.identifiers().get('race-member1');
        const member2 = await client2.identifiers().get('race-member2');
        const group = await client1.identifiers().get(groupName);
        stamp = new Date().toISOString().replace('Z', '000+00:00');

        proposeOps = await addEndRoleMultisig(
            client1,
            groupName,
            member1,
            [member2],
            group,
            stamp,
            true
        );

        expect(await client1.oobis().endroles(groupAid, 'agent')).toHaveLength(
            0
        );
        expect(await walletGateSaysReady(client1, 'half done', groupAid)).toBe(
            false
        );
    });

    await step('The second member co-signing authorises them all', async () => {
        const member1 = await client1.identifiers().get('race-member1');
        const member2 = await client2.identifiers().get('race-member2');
        const group = await client1.identifiers().get(groupName);

        const joinOps = await addEndRoleMultisig(
            client2,
            groupName,
            member2,
            [member1],
            group,
            stamp
        );
        await Promise.all([
            ...proposeOps.map((op: any) => waitOperation(client1, op)),
            ...joinOps.map((op: any) => waitOperation(client2, op)),
        ]);

        const roles = await client1.oobis().endroles(groupAid, 'agent');
        expect(roles.map((role: any) => role.eid).sort()).toEqual(expected);
        expect(await walletGateSaysReady(client1, 'complete', groupAid)).toBe(
            true
        );
    });

    await step('The other side sees the same agents', async () => {
        const groupOobi = await client1.oobis().get(groupName, 'agent');
        const oobiUrl = groupOobi.oobis[0].split('/agent/')[0];
        await resolveOobi(aliceClient, oobiUrl, groupName);

        const roles = await aliceClient.oobis().endroles(groupAid, 'agent');
        log('other side', 'agents it would record as controllers', roles);
        expect(roles.map((role: any) => role.eid).sort()).toEqual(expected);
    });
}, 120000);

// Fergal's acceptance scenario: 2-of-2, the initiator goes away right after
// initiating, the joiner joins, and nothing may be sent until the initiator is
// back and the authorisation reaches threshold.
test('a joiner holds the request back while the initiator is away', async () => {
    const groupName = 'agent-auth-away';
    const expected = [client1.agent!.pre, client2.agent!.pre].sort();
    let groupAid = '';
    let joinerOps: any[] = [];
    let stamp = '';
    let op1: any;

    await step('The initiator starts the group and goes away', async () => {
        op1 = await startMultisigIncept(client1, {
            groupName,
            localMemberName: 'away-member1',
            participants: [
                (await client1.identifiers().get('away-member1')).prefix,
                (await client2.identifiers().get('away-member2')).prefix,
            ],
            isith: 2,
            nsith: 2,
            toad: 3,
            wits: WITNESSES,
        });
        groupAid = (await client1.identifiers().get(groupName)).prefix;
        log('away', 'group proposed, only the initiator has signed', groupAid);
    });

    await step('KERIA refuses an end role on a half-signed group', async () => {
        stamp = new Date().toISOString().replace('Z', '000+00:00');
        await expect(
            client1
                .identifiers()
                .addEndRole(groupName, 'agent', client1.agent!.pre, stamp)
        ).rejects.toThrow(/500/);
        log('away', 'the hab exists but the end role add is refused');
    });

    await step('The joiner joins and the group completes', async () => {
        const notes = await waitForNotifications(client2, '/multisig/icp');
        await Promise.all(
            notes.map((note) => client2.notifications().mark(note.i))
        );
        const msgSaid = notes[notes.length - 1].a.d;
        assert(msgSaid, 'msgSaid not defined');

        const op2 = await acceptMultisigIncept(client2, {
            localMemberName: 'away-member2',
            groupName,
            msgSaid,
        });
        await waitOperation(client2, op2);
        log('away', 'the joiner has the group', groupAid);
    });

    await step('With the initiator away nothing is authorised', async () => {
        const member1 = await client1.identifiers().get('away-member1');
        const member2 = await client2.identifiers().get('away-member2');
        const group = await client2.identifiers().get(groupName);
        stamp = new Date().toISOString().replace('Z', '000+00:00');

        joinerOps = await addEndRoleMultisig(
            client2,
            groupName,
            member2,
            [member1],
            group,
            stamp,
            true
        );

        expect(await client2.oobis().endroles(groupAid, 'agent')).toHaveLength(
            0
        );
        expect(await walletGateSaysReady(client2, 'away', groupAid)).toBe(
            false
        );
    });

    await step('The initiator comes back and it goes out', async () => {
        const member1 = await client1.identifiers().get('away-member1');
        const member2 = await client2.identifiers().get('away-member2');
        const group = await client1.identifiers().get(groupName);

        await waitOperation(client1, op1);
        const backOps = await addEndRoleMultisig(
            client1,
            groupName,
            member1,
            [member2],
            group,
            stamp
        );
        await Promise.all([
            ...joinerOps.map((op: any) => waitOperation(client2, op)),
            ...backOps.map((op: any) => waitOperation(client1, op)),
        ]);

        const roles = await client2.oobis().endroles(groupAid, 'agent');
        expect(roles.map((role: any) => role.eid).sort()).toEqual(expected);
        expect(await walletGateSaysReady(client2, 'back', groupAid)).toBe(true);
    });
}, 180000);
