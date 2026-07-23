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

// SPIKE VT20-2942: rot (establishment) and ixn (iss/rev anchor) both land at
// state.s + 1. Two events at the same sn with split member sigs -> neither
// reaches threshold -> the group KEL stalls. Superseding decides the winner
// once one side reaches threshold (A0 rot>ixn, A1 rot!>rot, A2 ixn>nothing).

const WITS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

async function setup2of2(groupName: string) {
    const [client1, client2] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
    const [[aid1], [aid2]] = await Promise.all([
        getOrCreateIdentifier(client1, 'member1'),
        getOrCreateIdentifier(client2, 'member2'),
    ]);

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
        isith: 2,
        nsith: 2,
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
    assert.strictEqual(g.state.s, '0');
    console.log(`[setup] 2-of-2 group ${g.prefix} created at sn=${g.state.s}`);
    return { client1, client2, aid1, aid2, groupName, groupPrefix: g.prefix };
}

async function groupSn(client: any, groupName: string): Promise<string> {
    const hab = await client.identifiers().get(groupName);
    return hab.state.s;
}

function atcOf(serder: any, sigs: string[]): string {
    const sigers = sigs.map((s) => new signify.Siger({ qb64: s }));
    const ims = signify.d(signify.messagize(serder, sigers));
    return ims.substring(serder.size);
}

async function assertStall(client1: any, client2: any, groupName: string) {
    await new Promise((r) => setTimeout(r, 5000));
    const sn1 = await groupSn(client1, groupName);
    const sn2 = await groupSn(client2, groupName);
    console.log(
        `[stall] split sigs at sn=1 -> committed sn: member1=${sn1}, member2=${sn2} (KEL frozen at 0)`
    );
    assert.strictEqual(sn1, '0');
    assert.strictEqual(sn2, '0');
}

// rotate the two member AIDs and exchange the new key states, so a group rot
// can be built from the members' revealed next keys.
async function rotateMembersAndSyncStates(
    client1: any,
    client2: any
): Promise<any[]> {
    const r1 = await client1.identifiers().rotate('member1');
    await waitOperation(client1, await r1.op());
    const r2 = await client2.identifiers().rotate('member2');
    await waitOperation(client2, await r2.op());
    const a1 = await client1.identifiers().get('member1');
    const a2 = await client2.identifiers().get('member2');

    let q = await client1.keyStates().query(a2.prefix, '1');
    const a2State = (await waitOperation(client1, q)).response;
    q = await client2.keyStates().query(a1.prefix, '1');
    const a1State = (await waitOperation(client2, q)).response;
    console.log('[rotate] both member AIDs rotated to sn=1, key states exchanged');
    return [a1State, a2State];
}

test('rot and ixn race at the same sn (rot wins)', async () => {
    await signify.ready();
    const { client1, client2, aid1, aid2, groupName } =
        await setup2of2('race');

    let states: any[] = [];
    let ixnSaid = '';
    let rotSaid = '';

    await step('member1 submits a partial group ixn at sn=1', async () => {
        const data = { i: aid1, s: '0', d: aid1 };
        const res = await client1.identifiers().interact(groupName, data);
        await res.op();
        const serder = res.serder;
        ixnSaid = serder.said;
        assert.strictEqual(serder.sn, 1);
        console.log(`[ixn] member1 built ixn at sn=${serder.sad.s} said=${ixnSaid} (1/2 sigs -> escrow)`);
        const hab1 = await client1.identifiers().get('member1');
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/ixn',
                { gid: serder.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [serder, atcOf(serder, res.sigs)] },
                [aid2]
            );
    });

    await step('both members rotate their AIDs, member2 submits partial rot', async () => {
        states = await rotateMembersAndSyncStates(client1, client2);
        const res = await client2
            .identifiers()
            .rotate(groupName, { states, rstates: states });
        await res.op();
        const serder = res.serder;
        rotSaid = serder.said;
        assert.strictEqual(serder.sn, 1);
        console.log(`[rot] member2 built rot at sn=${serder.sad.s} said=${rotSaid} (1/2 sigs -> escrow, same sn as ixn)`);
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
    });

    await step('split sigs at sn=1 -> KEL stalls', async () => {
        await assertStall(client1, client2, groupName);
    });

    await step('member1 co-signs the rot -> rot commits, ixn dropped', async () => {
        const res = await client1
            .identifiers()
            .rotate(groupName, { states, rstates: states });
        const op = await res.op();
        const serder = res.serder;
        const hab1 = await client1.identifiers().get('member1');
        const smids = states.map((s) => s.i);
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/rot',
                { gid: serder.pre, smids, rmids: smids },
                { rot: [serder, atcOf(serder, res.sigs)] },
                [states[1].i]
            );
        await waitOperation(client1, op);
        const g = await client1.identifiers().get(groupName);
        console.log(`[result] group committed at sn=${g.state.s} et=${g.state.et} d=${g.state.d}`);
        console.log(`[result] rot ${rotSaid} WON (A0), ixn ${ixnSaid} DROPPED`);
        assert.strictEqual(g.state.s, '1');
        assert.strictEqual(g.state.et, 'rot');
        assert.strictEqual(g.state.d, rotSaid);
    });
}, 120000);

test('two ixns race at the same sn (A2: ixn supersedes nothing)', async () => {
    await signify.ready();
    const { client1, client2, aid1, aid2, groupName } =
        await setup2of2('race-ii');

    let ixnASaid = '';
    let ixnBSaid = '';
    let opA1: any;

    await step('member1 submits partial ixn A, member2 submits partial ixn B', async () => {
        const dataA = { i: aid1, s: '0', d: aid1 };
        const resA = await client1.identifiers().interact(groupName, dataA);
        opA1 = await resA.op();
        const serderA = resA.serder;
        ixnASaid = serderA.said;
        assert.strictEqual(serderA.sn, 1);
        console.log(`[ixn A] member1 built ixn A at sn=${serderA.sad.s} said=${ixnASaid} (1/2 -> escrow)`);
        const hab1 = await client1.identifiers().get('member1');
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/ixn',
                { gid: serderA.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [serderA, atcOf(serderA, resA.sigs)] },
                [aid2]
            );

        const dataB = { i: aid2, s: '0', d: aid2 };
        const resB = await client2.identifiers().interact(groupName, dataB);
        await resB.op();
        const serderB = resB.serder;
        ixnBSaid = serderB.said;
        assert.strictEqual(serderB.sn, 1);
        assert.notStrictEqual(ixnBSaid, ixnASaid);
        console.log(`[ixn B] member2 built ixn B at sn=${serderB.sad.s} said=${ixnBSaid} (1/2 -> escrow, same sn, different anchor)`);
        const hab2 = await client2.identifiers().get('member2');
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/ixn',
                { gid: serderB.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [serderB, atcOf(serderB, resB.sigs)] },
                [aid1]
            );
    });

    await step('split sigs at sn=1 -> KEL stalls', async () => {
        await assertStall(client1, client2, groupName);
    });

    await step('member2 joins ixn A -> A commits, B dropped', async () => {
        const dataA = { i: aid1, s: '0', d: aid1 };
        const res = await client2.identifiers().interact(groupName, dataA);
        const op = await res.op();
        const serder = res.serder;
        const hab2 = await client2.identifiers().get('member2');
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/ixn',
                { gid: serder.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [serder, atcOf(serder, res.sigs)] },
                [aid1]
            );
        await Promise.all([
            waitOperation(client1, opA1),
            waitOperation(client2, op),
        ]);
        const g = await client1.identifiers().get(groupName);
        console.log(`[result] group committed at sn=${g.state.s} et=${g.state.et} d=${g.state.d}`);
        console.log(`[result] ixn A ${ixnASaid} WON, ixn B ${ixnBSaid} DROPPED (A2: an ixn supersedes nothing)`);
        assert.strictEqual(g.state.s, '1');
        assert.strictEqual(g.state.et, 'ixn');
        assert.strictEqual(g.state.d, ixnASaid);
    });
}, 120000);

test('two divergent rots at the same sn wedge a 2-of-2 group', async () => {
    await signify.ready();
    const { client1, client2, aid1, aid2, groupName } =
        await setup2of2('race-rr');

    let states: any[] = [];
    let rotASaid = '';
    let rotBSaid = '';

    await step('both members rotate AIDs', async () => {
        states = await rotateMembersAndSyncStates(client1, client2);
    });

    await step('member1 submits rot A, member2 submits a different rot B', async () => {
        const sealA = { i: aid1, s: '0', d: aid1 };
        const resA = await client1
            .identifiers()
            .rotate(groupName, { states, rstates: states, data: [sealA] });
        await resA.op();
        const serderA = resA.serder;
        rotASaid = serderA.said;
        assert.strictEqual(serderA.sn, 1);
        console.log(`[rot A] member1 built rot A at sn=${serderA.sad.s} said=${rotASaid} (1/2 -> escrow)`);
        const hab1 = await client1.identifiers().get('member1');
        const smids = states.map((s) => s.i);
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/rot',
                { gid: serderA.pre, smids, rmids: smids },
                { rot: [serderA, atcOf(serderA, resA.sigs)] },
                [states[1].i]
            );

        const sealB = { i: aid2, s: '0', d: aid2 };
        const resB = await client2
            .identifiers()
            .rotate(groupName, { states, rstates: states, data: [sealB] });
        await resB.op();
        const serderB = resB.serder;
        rotBSaid = serderB.said;
        assert.strictEqual(serderB.sn, 1);
        assert.notStrictEqual(rotBSaid, rotASaid);
        console.log(`[rot B] member2 built rot B at sn=${serderB.sad.s} said=${rotBSaid} (1/2 -> escrow, same sn, different anchor)`);
        const hab2 = await client2.identifiers().get('member2');
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/rot',
                { gid: serderB.pre, smids, rmids: smids },
                { rot: [serderB, atcOf(serderB, resB.sigs)] },
                [states[0].i]
            );
    });

    await step('split sigs at sn=1 -> KEL stalls', async () => {
        await assertStall(client1, client2, groupName);
    });

    await step('neither member can switch to the other rot -> wedged', async () => {
        // member2 already signed rot B; its keeper is bound to that rotation at
        // sn=1, so it cannot produce a signature for the divergent rot A. No one
        // can push either rot to threshold -> the group stays stuck at sn=0.
        const sealA = { i: aid1, s: '0', d: aid1 };
        let threw = false;
        try {
            await client2
                .identifiers()
                .rotate(groupName, { states, rstates: states, data: [sealA] });
        } catch (e: any) {
            threw = true;
            console.log(`[result] member2 cannot co-sign rot A: ${e.message}`);
        }
        assert.strictEqual(threw, true);
        console.log(`[result] rot A ${rotASaid} and rot B ${rotBSaid} both stuck at 1/2 -> KEL wedged at sn=0 (needs out-of-band realignment)`);
        assert.strictEqual(await groupSn(client1, groupName), '0');
        assert.strictEqual(await groupSn(client2, groupName), '0');
    });
}, 120000);

// The designed flow: a group does not fix the rotation sn until every member has
// rotated their KEL, and a member only rotates once its outbox has cleared. So an
// in-flight issuance commits first, and the rotation lands on the next sn. Both
// succeed, no collision.
test('an issuance that completes before the rotation lands on the next sn (no race)', async () => {
    await signify.ready();
    const { client1, client2, aid1, aid2, groupName } =
        await setup2of2('race-seq');

    let ixnSaid = '';
    let rotSaid = '';

    await step('the group ixn commits at sn=1 while both members still hold their keys', async () => {
        const data = { i: aid1, s: '0', d: aid1 };
        const res1 = await client1.identifiers().interact(groupName, data);
        const op1 = await res1.op();
        const s1 = res1.serder;
        ixnSaid = s1.said;
        const hab1 = await client1.identifiers().get('member1');
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/ixn',
                { gid: s1.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [s1, atcOf(s1, res1.sigs)] },
                [aid2]
            );

        const res2 = await client2.identifiers().interact(groupName, data);
        const op2 = await res2.op();
        const s2 = res2.serder;
        const hab2 = await client2.identifiers().get('member2');
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/ixn',
                { gid: s2.pre, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [s2, atcOf(s2, res2.sigs)] },
                [aid1]
            );

        await Promise.all([
            waitOperation(client1, op1),
            waitOperation(client2, op2),
        ]);
        const g = await client1.identifiers().get(groupName);
        console.log(`[ixn] issuance committed at sn=${g.state.s} et=${g.state.et} said=${ixnSaid}`);
        assert.strictEqual(g.state.s, '1');
        assert.strictEqual(g.state.et, 'ixn');
    });

    await step('the rotation is built afterwards, so it lands at sn=2', async () => {
        const states = await rotateMembersAndSyncStates(client1, client2);
        const smids = states.map((s) => s.i);

        const res1 = await client1
            .identifiers()
            .rotate(groupName, { states, rstates: states });
        const op1 = await res1.op();
        const s1 = res1.serder;
        rotSaid = s1.said;
        assert.strictEqual(s1.sn, 2);
        const hab1 = await client1.identifiers().get('member1');
        await client1
            .exchanges()
            .send(
                'member1',
                'multisig',
                hab1,
                '/multisig/rot',
                { gid: s1.pre, smids, rmids: smids },
                { rot: [s1, atcOf(s1, res1.sigs)] },
                [states[1].i]
            );

        const res2 = await client2
            .identifiers()
            .rotate(groupName, { states, rstates: states });
        const op2 = await res2.op();
        const s2 = res2.serder;
        const hab2 = await client2.identifiers().get('member2');
        await client2
            .exchanges()
            .send(
                'member2',
                'multisig',
                hab2,
                '/multisig/rot',
                { gid: s2.pre, smids, rmids: smids },
                { rot: [s2, atcOf(s2, res2.sigs)] },
                [states[0].i]
            );

        await Promise.all([
            waitOperation(client1, op1),
            waitOperation(client2, op2),
        ]);
        const g = await client1.identifiers().get(groupName);
        console.log(`[rot] rotation committed at sn=${g.state.s} et=${g.state.et} said=${rotSaid}`);
        console.log(`[result] ixn at sn=1, rot at sn=2 -> different sn, no collision`);
        assert.strictEqual(g.state.s, '2');
        assert.strictEqual(g.state.et, 'rot');
        assert.notStrictEqual(rotSaid, ixnSaid);
    });
}, 120000);
