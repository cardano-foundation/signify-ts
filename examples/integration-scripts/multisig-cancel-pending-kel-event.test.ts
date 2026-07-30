import { strict as assert } from 'assert';
import signify, {
    Algos,
    CreateIdentiferArgs,
    HabState,
    Siger,
    d,
    messagize,
} from 'signify-ts';
import { createAIDMultisig } from './utils/multisig-utils';
import { resolveEnvironment } from './utils/resolve-env';
import {
    getOrCreateAID,
    getOrCreateClients,
    resolveOobi,
    waitAndMarkNotification,
    waitOperation,
} from './utils/test-util';

const { witnessIds } = resolveEnvironment();

const ALICE = 'cancel-kel-alice';
const BOB = 'cancel-kel-bob';
const GROUP = 'cancel-kel-group';

async function sendInteraction(
    client: signify.SignifyClient,
    member: HabState,
    otherMember: HabState,
    group: HabState,
    data: unknown
) {
    const result = await client.identifiers().interact(GROUP, data);
    const op = await result.op();
    const sigers = result.sigs.map((sig) => new Siger({ qb64: sig }));
    const message = d(messagize(result.serder, sigers));

    await client.exchanges().send(
        member.name,
        'multisig',
        member,
        '/multisig/ixn',
        {
            gid: group.prefix,
            smids: [member.prefix, otherMember.prefix],
            rmids: [member.prefix, otherMember.prefix],
        },
        {
            ixn: [result.serder, message.substring(result.serder.size)],
        },
        [otherMember.prefix]
    );

    return { op, serder: result.serder };
}

test('members cancel an exact pending group KEL event by SAID', async () => {
    await signify.ready();
    const [alice, bob] = await getOrCreateClients(2);

    const memberArgs: CreateIdentiferArgs = {
        toad: witnessIds.length,
        wits: witnessIds,
    };
    const [aliceAid, bobAid] = await Promise.all([
        getOrCreateAID(alice, ALICE, memberArgs),
        getOrCreateAID(bob, BOB, memberArgs),
    ]);

    const [aliceOobi, bobOobi] = await Promise.all([
        alice.oobis().get(ALICE, 'agent'),
        bob.oobis().get(BOB, 'agent'),
    ]);
    await Promise.all([
        resolveOobi(alice, bobOobi.oobis[0], BOB),
        resolveOobi(bob, aliceOobi.oobis[0], ALICE),
    ]);

    const states = [aliceAid.state, bobAid.state];
    const groupArgs: CreateIdentiferArgs = {
        algo: Algos.group,
        isith: 2,
        nsith: 2,
        toad: witnessIds.length,
        wits: witnessIds,
        states,
        rstates: states,
    };

    groupArgs.mhab = aliceAid;
    const aliceGroupOp = await createAIDMultisig(
        alice,
        aliceAid,
        [bobAid],
        GROUP,
        groupArgs,
        true
    );
    groupArgs.mhab = bobAid;
    const bobGroupOp = await createAIDMultisig(
        bob,
        bobAid,
        [aliceAid],
        GROUP,
        groupArgs
    );
    await Promise.all([
        waitOperation(alice, aliceGroupOp),
        waitOperation(bob, bobGroupOp),
    ]);

    const [aliceGroup, bobGroup] = await Promise.all([
        alice.identifiers().get(GROUP),
        bob.identifiers().get(GROUP),
    ]);
    assert.equal(aliceGroup.prefix, bobGroup.prefix);

    const [aliceCommitted, bobCommitted] = await Promise.all([
        alice.identifiers().getLatestEvent(GROUP),
        bob.identifiers().getLatestEvent(GROUP),
    ]);
    assert.equal(aliceCommitted.d, bobCommitted.d);
    assert.equal(parseInt(aliceCommitted.s, 16), 0);

    const pending = await sendInteraction(alice, aliceAid, bobAid, aliceGroup, {
        activity: 'issuance-anchor-to-cancel',
    });
    await waitAndMarkNotification(bob, '/multisig/ixn');

    const [alicePending, bobPending] = await Promise.all([
        alice.identifiers().getLatestEvent(GROUP),
        bob.identifiers().getLatestEvent(GROUP),
    ]);
    for (const latest of [alicePending, bobPending]) {
        assert.equal(latest.d, pending.serder.ked.d);
        assert.equal(parseInt(latest.s, 16), 1);
        assert.equal(latest.t, 'ixn');
    }

    await Promise.all([
        alice.identifiers().cancelEvent(GROUP, pending.serder.ked.d),
        bob.identifiers().cancelEvent(GROUP, pending.serder.ked.d),
    ]);

    const [aliceAfterCancel, bobAfterCancel] = await Promise.all([
        alice.identifiers().getLatestEvent(GROUP),
        bob.identifiers().getLatestEvent(GROUP),
    ]);
    for (const latest of [aliceAfterCancel, bobAfterCancel]) {
        assert.equal(latest.d, aliceCommitted.d);
        assert.equal(parseInt(latest.s, 16), 0);
    }

    const freshAlice = await sendInteraction(
        alice,
        aliceAid,
        bobAid,
        aliceGroup,
        { activity: 'fresh-after-cancel' }
    );
    await waitAndMarkNotification(bob, '/multisig/ixn');

    const [aliceFinal, bobFinal] = await Promise.all([
        alice.identifiers().getLatestEvent(GROUP),
        bob.identifiers().getLatestEvent(GROUP),
    ]);
    assert.equal(aliceFinal.d, freshAlice.serder.ked.d);
    assert.equal(bobFinal.d, freshAlice.serder.ked.d);
    assert.equal(parseInt(aliceFinal.s, 16), 1);

    await Promise.all([
        alice.identifiers().cancelEvent(GROUP, freshAlice.serder.ked.d),
        bob.identifiers().cancelEvent(GROUP, freshAlice.serder.ked.d),
    ]);
}, 240000);
