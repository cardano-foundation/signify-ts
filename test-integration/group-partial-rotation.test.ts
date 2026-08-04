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

// What happens to a 2-of-3 group while only some members have rotated.
//
// Three things under test:
//   1. a member that rotated drops out of the group key list, so it cannot sign
//   2. how many signers are left, and whether that still meets the threshold
//   3. whether KERIA accepts a group rot that leaves a laggard on its old key

const WITS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];

const GROUP = 'partial';

async function currentKey(client: any, alias: string): Promise<string> {
    const hab = await client.identifiers().get(alias);
    return hab.state.k[0];
}

// who can still produce a group signature: current key must be a slot in the
// group's key list, that is the lookup GroupKeeper.sign does
function slotsStillValid(groupKeys: string[], memberKeys: string[]): number[] {
    return memberKeys
        .map((key, i) => (groupKeys.includes(key) ? i : -1))
        .filter((i) => i >= 0);
}

async function trySign(client: any, label: string): Promise<string> {
    const gHab = await client.identifiers().get(GROUP);
    const keeper = client.manager.get(gHab);
    try {
        await keeper.sign(new TextEncoder().encode('anything'));
        return 'signed';
    } catch (e) {
        const message = (e as Error).message;
        console.log(`[sign] ${label} -> ${message}`);
        return message;
    }
}

test('a 2-of-3 group while only two members have rotated', async () => {
    await signify.ready();
    const [client1, client2, client3] = await Promise.all([
        getOrCreateClient(),
        getOrCreateClient(),
        getOrCreateClient(),
    ]);
    const [[aid1], [aid2], [aid3]] = await Promise.all([
        getOrCreateIdentifier(client1, 'member1'),
        getOrCreateIdentifier(client2, 'member2'),
        getOrCreateIdentifier(client3, 'member3'),
    ]);

    await step('create a 2-of-3 group', async () => {
        const [oobi1, oobi2, oobi3] = await Promise.all([
            client1.oobis().get('member1', 'agent'),
            client2.oobis().get('member2', 'agent'),
            client3.oobis().get('member3', 'agent'),
        ]);
        await Promise.all([
            resolveOobi(client1, oobi2.oobis[0], 'member2'),
            resolveOobi(client1, oobi3.oobis[0], 'member3'),
            resolveOobi(client2, oobi1.oobis[0], 'member1'),
            resolveOobi(client2, oobi3.oobis[0], 'member3'),
            resolveOobi(client3, oobi1.oobis[0], 'member1'),
            resolveOobi(client3, oobi2.oobis[0], 'member2'),
        ]);

        const op1 = await startMultisigIncept(client1, {
            groupName: GROUP,
            localMemberName: 'member1',
            participants: [aid1, aid2, aid3],
            toad: 2,
            isith: 2,
            nsith: 2,
            wits: WITS,
        });

        console.log('[setup] member1 sent the icp exn');

        const ops = [];
        for (const [client, alias] of [
            [client2, 'member2'],
            [client3, 'member3'],
        ] as const) {
            const notes = await waitForNotifications(client, '/multisig/icp');
            console.log(`[setup] ${alias} got ${notes.length} icp notification(s)`);
            await Promise.all(
                notes.map((note) => client.notifications().mark(note.i))
            );
            const msgSaid = notes[notes.length - 1].a.d;
            assert(msgSaid, 'msgSaid not defined');
            ops.push(
                await acceptMultisigIncept(client, {
                    localMemberName: alias,
                    groupName: GROUP,
                    msgSaid,
                })
            );
            console.log(`[setup] ${alias} joined`);
        }

        await waitOperation(client1, op1);
        console.log('[setup] member1 op done');
        await waitOperation(client2, ops[0]);
        console.log('[setup] member2 op done');
        await waitOperation(client3, ops[1]);
        console.log('[setup] member3 op done');

        const gHab = await client1.identifiers().get(GROUP);
        console.log(
            `[setup] group ${gHab.prefix} kt=${gHab.state.kt} nt=${gHab.state.nt}`
        );
        console.log(`[setup] group keys ${JSON.stringify(gHab.state.k)}`);
        assert.strictEqual(gHab.state.kt, '2');
        assert.strictEqual(gHab.state.k.length, 3);
    });

    await step('baseline: all three members are in the key list', async () => {
        const gHab = await client1.identifiers().get(GROUP);
        const keys = await Promise.all([
            currentKey(client1, 'member1'),
            currentKey(client2, 'member2'),
            currentKey(client3, 'member3'),
        ]);
        const valid = slotsStillValid(gHab.state.k, keys);
        console.log(`[baseline] members that can still sign: ${valid.length}/3`);
        assert.strictEqual(valid.length, 3);

        const result = await trySign(client1, 'member1 before rotating');
        assert.strictEqual(result, 'signed');
    });

    await step('member1 and member2 rotate their own AIDs', async () => {
        const r1 = await client1.identifiers().rotate('member1');
        await waitOperation(client1, await r1.op());
        const r2 = await client2.identifiers().rotate('member2');
        await waitOperation(client2, await r2.op());
        console.log('[rotate] member1 and member2 rotated, member3 did not');
    });

    await step('two of three slots are now dead', async () => {
        const gHab = await client1.identifiers().get(GROUP);
        const keys = await Promise.all([
            currentKey(client1, 'member1'),
            currentKey(client2, 'member2'),
            currentKey(client3, 'member3'),
        ]);
        const valid = slotsStillValid(gHab.state.k, keys);
        console.log(`[after] group keys   ${JSON.stringify(gHab.state.k)}`);
        console.log(`[after] member keys  ${JSON.stringify(keys)}`);
        console.log(
            `[after] members that can still sign: ${valid.length}/3, threshold is ${gHab.state.kt}`
        );
        assert.strictEqual(valid.length, 1);
        assert(
            valid.length < parseInt(gHab.state.kt, 16),
            'expected the group to be below its signing threshold'
        );
    });

    await step('a rotated member cannot sign for the group', async () => {
        // main rejects on the explicit csi < 0 check in GroupKeeper.sign. Older
        // signify (what the wallet pins) has no such check and falls through to
        // the salty keeper, which rejects the -1 index instead. Same outcome.
        const rotated = await trySign(client1, 'member1 after rotating');
        assert(
            rotated.includes('not present in current group signing keys') ||
                rotated.includes('Invalid signing index'),
            `expected the group signature to be refused, got: ${rotated}`
        );

        const notRotated = await trySign(client3, 'member3, never rotated');
        assert.strictEqual(notRotated, 'signed');
    });

    await step('can we rotate the group leaving member3 behind', async () => {
        // member1 and member2 moved to sn 1, member3 is still at its inception
        const q2 = await client1.keyStates().query(aid2, '1');
        const q3 = await client1.keyStates().query(aid3, '0');
        await Promise.all([
            waitOperation(client1, q2),
            waitOperation(client1, q3),
        ]);

        const members = await client1.identifiers().members(GROUP);
        const order = members.signing.map((m: { aid: string }) => m.aid);
        const states = await Promise.all(
            order.map(async (pre: string) => {
                const [state] = await client1.keyStates().get(pre);
                return state;
            })
        );
        console.log(`[partial] member order ${JSON.stringify(order)}`);
        console.log(
            `[partial] states sn: ${states
                .map((s: any) => `${s.i.slice(0, 8)}=${s.s}`)
                .join(' ')} (member3 never rotated)`
        );

        // client2 needs the same view before it can sign the same rot
        const p1 = await client2.keyStates().query(aid1, '1');
        const p3 = await client2.keyStates().query(aid3, '0');
        await Promise.all([
            waitOperation(client2, p1),
            waitOperation(client2, p3),
        ]);

        // a 2-of-3 rot needs two signatures, so both rotated members submit it
        const ops: any[] = [];
        for (const [client, label] of [
            [client1, 'member1'],
            [client2, 'member2'],
        ] as const) {
            try {
                const res = await client
                    .identifiers()
                    .rotate(GROUP, { states, rstates: states });
                ops.push([client, label, await res.op()]);
                console.log(`[partial] ${label} submitted the rot, accepted`);
            } catch (e) {
                console.log(`[partial] ${label} REFUSED: ${(e as Error).message}`);
            }
        }

        // poll by hand so a stuck operation can be inspected instead of aborting
        for (const [client, label, op] of ops) {
            let current = op;
            for (let i = 0; i < 40; i++) {
                current = await client.operations().get(op.name);
                if (current.done) break;
                await new Promise((r) => setTimeout(r, 1000));
            }
            console.log(
                `[partial] ${label} op done=${current.done} error=${JSON.stringify(
                    current.error
                )}`
            );
        }

        const after = await client1.identifiers().get(GROUP);
        console.log(`[partial] group keys now ${JSON.stringify(after.state.k)}`);
        console.log(`[partial] group sn now ${after.state.s}`);
    });
}, 300000);
