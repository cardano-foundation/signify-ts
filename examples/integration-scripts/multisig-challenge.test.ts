import { strict as assert } from 'assert';
import signify, { Serder, Siger, SignifyClient } from 'signify-ts';
import {
    assertOperations,
    getOrCreateClient,
    getOrCreateIdentifier,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util';
import {
    acceptMultisigIncept,
    addEndRoleMultisig,
    startMultisigIncept,
} from './utils/multisig-utils';

const WITNESS_AIDS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

// All members must use the same datetime to produce the same exn SAID.
async function createChallengeResponseExn(
    client: SignifyClient,
    groupName: string,
    recipientPrefix: string,
    words: string[],
    datetime: string
): Promise<[Serder, string[], string]> {
    const groupHab = await client.identifiers().get(groupName);
    return client
        .exchanges()
        .createExchangeMessage(
            groupHab,
            '/challenge/response',
            { words },
            {},
            recipientPrefix,
            datetime
        );
}

// Coordination step: notifies peers via /multisig/exn so they co-sign. Does NOT deliver to recipient.
async function notifyPeersMultisigChallengeResponse(
    client: SignifyClient,
    memberName: string,
    groupName: string,
    exn: Serder,
    sigs: string[],
    otherMemberPrefixes: string[]
): Promise<void> {
    const groupHab = await client.identifiers().get(groupName);
    const memberHab = await client.identifiers().get(memberName);

    const mstate = groupHab.state;
    const seal = [
        'SealEvent',
        { i: groupHab.prefix, s: mstate['ee']['s'], d: mstate['ee']['d'] },
    ];
    const sigers = sigs.map((sig) => new Siger({ qb64: sig }));
    const ims = signify.d(signify.messagize(exn, sigers, seal));
    const exnAtc = ims.substring(exn.size);

    await client
        .exchanges()
        .send(
            memberName,
            'multisig',
            memberHab,
            '/multisig/exn',
            { gid: groupHab.prefix },
            { exn: [exn, exnAtc] },
            otherMemberPrefixes
        );
}

// Delivers fully multi-signed challenge response. Must be called by each member.
async function sendGroupChallengeResponse(
    client: SignifyClient,
    groupName: string,
    exn: Serder,
    allSigs: string[],
    recipientPrefix: string
): Promise<any> {
    const res = await client
        .exchanges()
        .sendFromEvents(groupName, 'challenge', exn, allSigs, '', [
            recipientPrefix,
        ]);
    return res;
}

test(
    'multisig challenge response — group 2-of-2 responds to single-sig requestor',
    async () => {
        await signify.ready();

        const [clientAlice, clientM1, clientM2] = await Promise.all([
            getOrCreateClient(),
            getOrCreateClient(),
            getOrCreateClient(),
        ]);

        // Create individual AIDs
        const [[aidAlice], [aidM1], [aidM2]] = await Promise.all([
            getOrCreateIdentifier(clientAlice, 'alice'),
            getOrCreateIdentifier(clientM1, 'member1'),
            getOrCreateIdentifier(clientM2, 'member2'),
        ]);
        console.log('Alice AID:', aidAlice);
        console.log('Member1 AID:', aidM1);
        console.log('Member2 AID:', aidM2);

        // Members exchange OOBIs
        const [oobi1, oobi2] = await Promise.all([
            clientM1.oobis().get('member1', 'agent'),
            clientM2.oobis().get('member2', 'agent'),
        ]);
        await Promise.all([
            resolveOobi(clientM1, oobi2.oobis[0], 'member2'),
            resolveOobi(clientM2, oobi1.oobis[0], 'member1'),
        ]);
        console.log('Members exchanged OOBIs');

        // Create 2-of-2 multisig group
        const GROUP_NAME = 'responder';
        const [icpOp1, icpOp2] = await Promise.all([
            startMultisigIncept(clientM1, {
                groupName: GROUP_NAME,
                localMemberName: 'member1',
                participants: [aidM1, aidM2],
                isith: 2,
                nsith: 2,
                toad: WITNESS_AIDS.length,
                wits: WITNESS_AIDS,
            }),
            (async () => {
                const notes = await waitForNotifications(
                    clientM2,
                    '/multisig/icp'
                );
                await Promise.all(
                    notes.map((n) => clientM2.notifications().mark(n.i))
                );
                const msgSaid = notes[notes.length - 1].a.d;
                assert(msgSaid, 'msgSaid not defined');
                return acceptMultisigIncept(clientM2, {
                    groupName: GROUP_NAME,
                    localMemberName: 'member2',
                    msgSaid,
                });
            })(),
        ]);
        await Promise.all([
            waitOperation(clientM1, icpOp1),
            waitOperation(clientM2, icpOp2),
        ]);
        const groupHab = await clientM1.identifiers().get(GROUP_NAME);
        const groupAID = groupHab.prefix;
        console.log('Multisig group created:', groupAID);

        // Authorize agent end role for the group
        const stamp = new Date().toISOString().replace('Z', '000+00:00');
        const [multisigHab1, multisigHab2, member1Hab, member2Hab] =
            await Promise.all([
                clientM1.identifiers().get(GROUP_NAME),
                clientM2.identifiers().get(GROUP_NAME),
                clientM1.identifiers().get('member1'),
                clientM2.identifiers().get('member2'),
            ]);
        const [endOps1, endOps2] = await Promise.all([
            addEndRoleMultisig(
                clientM1,
                GROUP_NAME,
                member1Hab,
                [member2Hab],
                multisigHab1,
                stamp,
                true
            ),
            addEndRoleMultisig(
                clientM2,
                GROUP_NAME,
                member2Hab,
                [member1Hab],
                multisigHab2,
                stamp,
                false
            ),
        ]);
        await Promise.all([
            ...endOps1.map((op: any) => waitOperation(clientM1, op)),
            ...endOps2.map((op: any) => waitOperation(clientM2, op)),
        ]);
        console.log('Group agent end roles authorized');

        // Cross OOBI resolution
        const [aliceOobi, groupOobi] = await Promise.all([
            clientAlice.oobis().get('alice', 'agent'),
            clientM1.oobis().get(GROUP_NAME, 'agent'),
        ]);
        await Promise.all([
            resolveOobi(clientAlice, groupOobi.oobis[0], GROUP_NAME),
            resolveOobi(clientM1, aliceOobi.oobis[0], 'alice'),
            resolveOobi(clientM2, aliceOobi.oobis[0], 'alice'),
        ]);
        console.log('Cross OOBIs resolved: Alice knows group, group members know Alice');

        // Alice generates challenge and starts verify op
        const challenge = await clientAlice.challenges().generate(128);
        console.log('Alice generated challenge words');

        const verifyOp = await clientAlice
            .challenges()
            .verify(groupAID, challenge.words);
        console.log(
            'Alice started challenge verify operation for group AID:',
            groupAID
        );

        // Group responds to challenge
        const aliceHabState = await clientAlice.identifiers().get('alice');
        const alicePrefix = aliceHabState.prefix;

        // Member1 creates the /challenge/response exn and picks a datetime
        const datetime = new Date().toISOString().replace('Z', '000+00:00');
        const [exn1, sigs1] = await createChallengeResponseExn(
            clientM1,
            GROUP_NAME,
            alicePrefix,
            challenge.words,
            datetime
        );

        // Member1 notifies Member2 via /multisig/exn
        await notifyPeersMultisigChallengeResponse(
            clientM1,
            'member1',
            GROUP_NAME,
            exn1,
            sigs1,
            [aidM2]
        );
        console.log(
            'Member1 created challenge response exn and notified Member2 via /multisig/exn'
        );

        // Member2 receives /multisig/exn notification and extracts the exn from the embed
        const m2Notes = await waitForNotifications(clientM2, '/multisig/exn');
        await Promise.all(m2Notes.map((n) => clientM2.notifications().mark(n.i)));

        // Fetch the coordination message to extract the embedded exn's datetime
        const msgSaid = m2Notes[m2Notes.length - 1].a.d;
        assert(msgSaid, 'notification must have a SAID');
        const multisigExnRes = await clientM2.groups().getRequest(msgSaid);
        const embeddedExn = multisigExnRes[0].exn.e.exn;
        const extractedDatetime = embeddedExn.dt as string;
        assert(extractedDatetime, 'embedded exn must have a dt field');

        // Member2 co-signs using the datetime from the embed
        const [exn2, sigs2] = await createChallengeResponseExn(
            clientM2,
            GROUP_NAME,
            alicePrefix,
            challenge.words,
            extractedDatetime
        );

        // Sanity check: same SAID
        assert.equal(
            exn1.ked.d,
            exn2.ked.d,
            'Both exns must share the same SAID (same datetime → same content)'
        );

        // Combine sigs and deliver — both members must submit for KERIA to process the multisig exchange
        const allSigs = [...sigs1, ...sigs2];

        await Promise.all([
            sendGroupChallengeResponse(
                clientM1,
                GROUP_NAME,
                exn1,
                allSigs,
                alicePrefix
            ),
            sendGroupChallengeResponse(
                clientM2,
                GROUP_NAME,
                exn2,
                allSigs,
                alicePrefix
            ),
        ]);
        console.log(
            'Both members submitted fully-signed challenge response'
        );

        // Give KERIA time to forward the challenge response to Alice's agent
        await new Promise((r) => setTimeout(r, 5000));

        // Alice waits for verify op and marks response as accepted
        const completedOp = await waitOperation(clientAlice, verifyOp);
        console.log('Alice challenge verify op completed');

        const verifyResponse = completedOp.response as {
            exn: Record<string, unknown>;
        };
        const exnSerder = new Serder(verifyResponse.exn);
        await clientAlice
            .challenges()
            .responded(groupAID, exnSerder.ked.d as string);
        console.log('Alice marked multisig challenge response as accepted');

        // Verify contact record shows challenge authenticated
        const contactsAfter = await clientAlice.contacts().list();
        const responderAfter = contactsAfter.find(
            (c: any) => c.alias === GROUP_NAME
        );
        assert(responderAfter, 'responder contact not found');
        assert(
            Array.isArray(responderAfter.challenges),
            'responder contact should have challenges array'
        );
        assert(
            responderAfter.challenges.length > 0,
            'responder contact should have at least one challenge'
        );
        expect(responderAfter.challenges[0].authenticated).toBe(true);

        await assertOperations(clientAlice, clientM1, clientM2);
    },
    180000
);
