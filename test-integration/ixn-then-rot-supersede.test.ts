import signify from 'signify-ts';
import {
    getOrCreateClient,
    getOrCreateIdentifier,
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

// SPIKE VT20-2942 outcome 2: an ixn commits at sn=N, then a rot at the same sn
// supersedes it (recovery rule A0), forking the KEL and undoing the anchored
// issuance. This is unreachable in a 2-of-2 (committing the ixn needs both old
// keys, but the rot needs both members on their new keys). It IS reachable in a
// 1-of-2, where one member commits the ixn alone and the other, never syncing
// the group, commits a rot at the same sn on its own.

const WITS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

function atcOf(serder: any, sigs: string[]): string {
    const sigers = sigs.map((s) => new signify.Siger({ qb64: s }));
    const ims = signify.d(signify.messagize(serder, sigers));
    return ims.substring(serder.size);
}

test('ixn commits then a rot at the same sn supersedes it', async () => {
    await signify.ready();
    const [client1, client2] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
    const [[aid1], [aid2]] = await Promise.all([
        getOrCreateIdentifier(client1, 'member1'),
        getOrCreateIdentifier(client2, 'member2'),
    ]);

    const groupName = 'supersede';
    let groupPrefix = '';

    await step('create a 1-of-2 multisig group', async () => {
        const oobi1 = await client1.oobis().get('member1', 'agent');
        const oobi2 = await client2.oobis().get('member2', 'agent');
        await Promise.all([
            resolveOobi(client1, oobi2.oobis[0], 'member2'),
            resolveOobi(client2, oobi1.oobis[0], 'member1'),
        ]);

        const op1 = await startMultisigIncept(client1, {
            groupName,
            localMemberName: 'member1',
            participants: [aid1, aid2],
            toad: 2,
            isith: 1,
            nsith: 1,
            wits: WITS,
        });
        const notes = await waitForNotifications(client2, '/multisig/icp');
        await Promise.all(notes.map((n) => client2.notifications().mark(n.i)));
        const msgSaid = notes[notes.length - 1].a.d;
        assert(msgSaid, 'msgSaid not defined');
        const op2 = await acceptMultisigIncept(client2, {
            localMemberName: 'member2',
            groupName,
            msgSaid,
        });
        await Promise.all([
            waitOperation(client1, op1),
            waitOperation(client2, op2),
        ]);
        const g = await client1.identifiers().get(groupName);
        groupPrefix = g.prefix;
        assert.strictEqual(g.state.s, '0');
        console.log(`[setup] 1-of-2 group ${groupPrefix} created at sn=${g.state.s}`);
    });

    // member1 anchors an issuance-style ixn and commits it alone (isith=1).
    // member2 never receives it, so member2's group view stays at sn=0.
    let ixnSaid = '';
    await step('member1 commits an ixn alone at sn=1', async () => {
        const data = { i: aid1, s: '0', d: aid1 };
        const res = await client1.identifiers().interact(groupName, data);
        const op = await res.op();
        const serder = res.serder;
        ixnSaid = serder.said;
        assert.strictEqual(serder.sn, 1);
        await waitOperation(client1, op);
        const g = await client1.identifiers().get(groupName);
        console.log(`[ixn] member1 committed ixn alone at sn=${g.state.s} et=${g.state.et} said=${ixnSaid}`);
        assert.strictEqual(g.state.s, '1');
        assert.strictEqual(g.state.et, 'ixn');
        assert.strictEqual(g.state.d, ixnSaid);
    });

    // Rotation path: both members reveal their next member keys. member2 builds
    // and commits a group rot alone (nsith=1) at sn=1, from its stale sn=0 view.
    let rotSaid = '';
    await step('member2 commits a rot alone at the same sn=1', async () => {
        const r1 = await client1.identifiers().rotate('member1');
        await waitOperation(client1, await r1.op());
        const r2 = await client2.identifiers().rotate('member2');
        await waitOperation(client2, await r2.op());
        const a1 = await client1.identifiers().get('member1');

        const q = await client2.keyStates().query(a1.prefix, '1');
        const a1State = (await waitOperation(client2, q)).response;
        const a2State = (await client2.keyStates().get(aid2))[0];
        const states = [a1State, a2State];

        const res = await client2
            .identifiers()
            .rotate(groupName, { states, rstates: states });
        const op = await res.op();
        const serder = res.serder;
        rotSaid = serder.said;
        assert.strictEqual(serder.sn, 1);
        assert.notStrictEqual(rotSaid, ixnSaid);
        console.log(`[rot] member2 built rot alone at sn=${serder.sad.s} said=${rotSaid} (from stale sn=0 view, same sn as the committed ixn)`);

        const hab2 = await client2.identifiers().get('member2');
        const smids = states.map((s) => s.i);
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/rot',
                { gid: serder.pre, smids, rmids: smids },
                { rot: [serder, atcOf(serder, res.sigs)] },
                [states[0].i]
            );
        await waitOperation(client2, op);
    });

    await step('rot supersedes the ixn: sn=1 now holds the rot', async () => {
        const g2 = await client2.identifiers().get(groupName);
        console.log(`[result] group at sn=${g2.state.s} et=${g2.state.et} d=${g2.state.d}`);
        console.log(`[result] rot ${rotSaid} SUPERSEDED ixn ${ixnSaid} at sn=1 (A0) -> issuance anchor undone`);
        assert.strictEqual(g2.state.s, '1');
        assert.strictEqual(g2.state.et, 'rot');
        assert.strictEqual(g2.state.d, rotSaid);

        // the committed event at sn=1 is no longer the ixn -> issuance undone
        assert.notStrictEqual(g2.state.d, ixnSaid);
    });
}, 120000);
