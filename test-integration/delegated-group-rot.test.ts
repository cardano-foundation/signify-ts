import signify from 'signify-ts';
import {
    createAID,
    getOrCreateClient,
    getOrCreateContact,
    markAndRemoveNotification,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util.ts';
import {
    acceptMultisigIncept,
    startMultisigIncept,
} from './utils/multisig-utils.ts';
import { assert, test } from 'vitest';
import { step } from './utils/test-step.ts';

// Whether a delegated group can rotate at all.
//
// The wallet builds a group rotation with createRotationData and has no
// delegation-specific code, relying on signify picking drt off hab.state.di.
// Nothing exercises the two together, so this walks a delegated 2-of-2 group
// through a full round: both members rotate, the group rot is built, the
// delegator anchors it, and the group has to reach sn 1.
//
// The delegator is single-sig on purpose. In production it is a group, but that
// only changes how the approval is signed, not what the delegate builds.

const WITS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

const GROUP = 'delegated_group';

// mirrors multiSigService.continueGroupRotation: build the group rot from every
// member's current key state, then tell the other members about it
async function buildGroupRot(
    client: any,
    memberAlias: string,
    states: any[]
): Promise<any> {
    const res = await client
        .identifiers()
        .rotate(GROUP, { states, rstates: states });
    const op = await res.op();

    const serder = res.serder;
    const sigers = res.sigs.map(
        (sig: string) => new signify.Siger({ qb64: sig })
    );
    const ims = signify.d(signify.messagize(serder, sigers));
    const atc = ims.substring(serder.size);

    const mHab = await client.identifiers().get(memberAlias);
    const members = await client.identifiers().members(GROUP);
    const smids = members.signing.map((member: { aid: string }) => member.aid);
    const recp = smids.filter((prefix: string) => prefix !== mHab.prefix);

    const [exn, exnSigs, exnAtc] = await client
        .exchanges()
        .createExchangeMessage(
            mHab,
            '/multisig/rot',
            { gid: serder.pre, smids, rmids: smids },
            { rot: [serder, atc] },
            recp[0]
        );
    await client
        .exchanges()
        .sendFromEvents(mHab.prefix, 'multisig', exn, exnSigs, exnAtc, recp);

    return { serder, op };
}

async function groupSn(client: any): Promise<string> {
    const gHab = await client.identifiers().get(GROUP);
    return gHab.state.s;
}

// the delegate side cannot move until the approval is in its own KEL copy
async function pullAnchor(clients: any[], delpre: string, anchor: any) {
    await Promise.all(
        clients.map(async (client) => {
            const q = await client.keyStates().query(delpre, undefined, anchor);
            await waitOperation(client, q);
        })
    );
}

test('a delegated group can complete a rotation round', async () => {
    await signify.ready();
    const [delegatorClient, client1, client2] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
    const clients = [client1, client2];

    const [delegatorAid, aid1, aid2] = await Promise.all([
        createAID(delegatorClient, 'authority'),
        createAID(client1, 'member1'),
        createAID(client2, 'member2'),
    ]);
    const delpre = delegatorAid.prefix;
    const aids = [aid1.prefix, aid2.prefix];

    await step('members and delegator resolve each other', async () => {
        const [oobi1, oobi2, delegatorOobi] = await Promise.all([
            client1.oobis().get('member1', 'agent'),
            client2.oobis().get('member2', 'agent'),
            delegatorClient.oobis().get('authority', 'agent'),
        ]);

        await Promise.all([
            resolveOobi(client1, oobi2.oobis[0], 'member2'),
            resolveOobi(client2, oobi1.oobis[0], 'member1'),
            getOrCreateContact(client1, 'authority', delegatorOobi.oobis[0]),
            getOrCreateContact(client2, 'authority', delegatorOobi.oobis[0]),
        ]);
    });

    let groupPre = '';

    await step('incept a 2-of-2 group delegated to the authority', async () => {
        const op1 = await startMultisigIncept(client1, {
            groupName: GROUP,
            localMemberName: 'member1',
            participants: aids,
            isith: 2,
            nsith: 2,
            toad: 2,
            wits: WITS,
            delpre,
        });

        const [note] = await waitForNotifications(client2, '/multisig/icp');
        await markAndRemoveNotification(client2, note);
        assert(note.a.d, 'no icp notification said');
        const op2 = await acceptMultisigIncept(client2, {
            groupName: GROUP,
            localMemberName: 'member2',
            msgSaid: note.a.d,
        });

        const pending = await client1.identifiers().get(GROUP);
        groupPre = pending.prefix;
        process.stdout.write(
            `[icp] delegated group ${groupPre}, waiting for approval\n`
        );

        // a dip is forced to a digestive prefix, so at sn 0 the said is the prefix
        const anchor = { i: groupPre, s: '0', d: groupPre };
        const approval = await delegatorClient
            .identifiers()
            .interact('authority', anchor);
        await waitOperation(delegatorClient, await approval.op());

        await pullAnchor(clients, delpre, anchor);
        await waitOperation(client1, op1);
        await waitOperation(client2, op2);

        const gHab = await client1.identifiers().get(GROUP);
        assert.strictEqual(gHab.state.di, delpre, 'group is not delegated');
        assert.strictEqual(gHab.state.s, '0');
        process.stdout.write(`[icp] approved, di=${gHab.state.di}\n`);
    });

    let states: any[] = [];

    await step('both members rotate their own AIDs', async () => {
        for (const [i, client] of clients.entries()) {
            const res = await client.identifiers().rotate(`member${i + 1}`);
            await waitOperation(client, await res.op());
        }

        states = await Promise.all(
            aids.map(async (aid) => {
                const q = await client1.keyStates().query(aid, '1');
                return (await waitOperation(client1, q)).response;
            })
        );
        await Promise.all(
            aids.map(async (aid) => {
                const q = await client2.keyStates().query(aid, '1');
                await waitOperation(client2, q);
            })
        );
        process.stdout.write('[rotate] both member AIDs rotated\n');
    });

    let rotSaid = '';
    let ops: any[] = [];

    await step('the group rot is built as a drt', async () => {
        const built1 = await buildGroupRot(client1, 'member1', states);
        const built2 = await buildGroupRot(client2, 'member2', states);
        ops = [built1.op, built2.op];

        process.stdout.write(
            `[build] ilk=${built1.serder.sad.t} sn=${built1.serder.sad.s} op=${built1.op.name}\n`
        );
        assert.strictEqual(
            built1.serder.sad.t,
            'drt',
            'a delegated group did not build a drt'
        );
        assert.strictEqual(
            built1.serder.sad.d,
            built2.serder.sad.d,
            'members built different rotation events'
        );
        // a drt carries no di, the dip established the delegation already
        rotSaid = built1.serder.sad.d;
    });

    // the local KEL moves as soon as the members sign, so the operation is what
    // says whether the delegator has let it through
    await step('the operation waits for the delegator', async () => {
        let done = false;
        for (let i = 0; i < 10; i++) {
            const states = await Promise.all(
                clients.map((client, j) => client.operations().get(ops[j].name))
            );
            done = states.every((op) => op.done);
            if (done) break;
            await new Promise((r) => setTimeout(r, 1000));
        }
        process.stdout.write(
            `[before] rotation op done after 10s without approval: ${done}\n`
        );
        assert.strictEqual(done, false, 'rotation completed without approval');
    });

    await step('the delegator anchors it and the round completes', async () => {
        const anchor = { i: groupPre, s: '1', d: rotSaid };
        const approval = await delegatorClient
            .identifiers()
            .interact('authority', anchor);
        await waitOperation(delegatorClient, await approval.op());

        await pullAnchor(clients, delpre, anchor);
        await Promise.all(
            clients.map((client, i) => waitOperation(client, ops[i]))
        );

        const sn = await groupSn(client1);
        process.stdout.write(`[after] group sn: ${sn}\n`);
        assert.strictEqual(sn, '1', 'group did not rotate after approval');

        const gHab = await client1.identifiers().get(GROUP);
        const memberKeys = states.map((state: any) => state.k[0]);
        assert.deepStrictEqual(
            [...gHab.state.k].sort(),
            [...memberKeys].sort(),
            'group keys did not catch up with the rotated members'
        );
        assert.strictEqual(gHab.state.di, delpre, 'group lost its delegator');
    });
}, 600000);
