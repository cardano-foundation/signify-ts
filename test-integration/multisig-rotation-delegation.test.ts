import { assert, test } from 'vitest';
import signify, {
    CreateIdentiferArgs,
    HabState,
    SignifyClient,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env.ts';
import {
    waitOperation,
    getOrCreateAID,
    getOrCreateClients,
    getOrCreateContact,
    createTimestamp,
    waitAndMarkNotification,
} from './utils/test-util.ts';
import {
    addEndRoleMultisig,
    createAIDMultisig,
    delegateMultisig,
} from './utils/multisig-utils.ts';

const { vleiServerUrl, witnessIds } = resolveEnvironment();

test('multisig-delegate-rotation', async function run() {
    const [clientDEL1, clientDEL2, clientDEE1, clientDEE2] =
        await getOrCreateClients(4);

    const kargsAID = {
        toad: witnessIds.length,
        wits: witnessIds,
    };

    const [aidDEL1, aidDEL2, aidDEE1, aidDEE2] = await Promise.all([
        getOrCreateAID(clientDEL1, 'DEL1', kargsAID),
        getOrCreateAID(clientDEL2, 'DEL2', kargsAID),
        getOrCreateAID(clientDEE1, 'DEE1', kargsAID),
        getOrCreateAID(clientDEE2, 'DEE2', kargsAID),
    ]);

    const [oobiDEL1, oobiDEL2, oobiDEE1, oobiDEE2] = await Promise.all([
        clientDEL1.oobis().get('DEL1', 'agent'),
        clientDEL2.oobis().get('DEL2', 'agent'),
        clientDEE1.oobis().get('DEE1', 'agent'),
        clientDEE2.oobis().get('DEE2', 'agent'),
    ]);

    await Promise.all([
        getOrCreateContact(clientDEL1, 'DEL2', oobiDEL2.oobis[0]),
        getOrCreateContact(clientDEL2, 'DEL1', oobiDEL1.oobis[0]),
        getOrCreateContact(clientDEE1, 'DEE2', oobiDEE2.oobis[0]),
        getOrCreateContact(clientDEE2, 'DEE1', oobiDEE1.oobis[0]),
    ]);

    let aidDELbyDEL1, aidDELbyDEL2: HabState;
    try {
        aidDELbyDEL1 = await clientDEL1.identifiers().get('DELEGATOR');
        aidDELbyDEL2 = await clientDEL2.identifiers().get('DELEGATOR');
    } catch {
        const rstates = [aidDEL1.state, aidDEL2.state];
        const states = rstates;

        const kargsMultisigAID: CreateIdentiferArgs = {
            algo: signify.Algos.group,
            isith: ['1/2', '1/2'],
            nsith: ['1/2', '1/2'],
            toad: kargsAID.toad,
            wits: kargsAID.wits,
            states: states,
            rstates: rstates,
        };

        kargsMultisigAID.mhab = aidDEL1;
        const multisigAIDOp1 = await createAIDMultisig(
            clientDEL1,
            aidDEL1,
            [aidDEL2],
            'DELEGATOR',
            kargsMultisigAID,
            true
        );

        kargsMultisigAID.mhab = aidDEL2;
        const multisigAIDOp2 = await createAIDMultisig(
            clientDEL2,
            aidDEL2,
            [aidDEL1],
            'DELEGATOR',
            kargsMultisigAID
        );

        await Promise.all([
            waitOperation(clientDEL1, multisigAIDOp1),
            waitOperation(clientDEL2, multisigAIDOp2),
        ]);

        await waitAndMarkNotification(clientDEL1, '/multisig/icp');

        aidDELbyDEL1 = await clientDEL1.identifiers().get('DELEGATOR');
        aidDELbyDEL2 = await clientDEL2.identifiers().get('DELEGATOR');
    }
    assert.equal(aidDELbyDEL1.prefix, aidDELbyDEL2.prefix);
    assert.equal(aidDELbyDEL1.name, aidDELbyDEL2.name);
    const aidDELEGATOR = aidDELbyDEL1;

    let [oobiDELbyDEL1, oobiDELbyDEL2] = await Promise.all([
        clientDEL1.oobis().get(aidDELEGATOR.name, 'agent'),
        clientDEL2.oobis().get(aidDELEGATOR.name, 'agent'),
    ]);
    if (oobiDELbyDEL1.oobis.length == 0 || oobiDELbyDEL2.oobis.length == 0) {
        const timestamp = createTimestamp();
        const opList1 = await addEndRoleMultisig(
            clientDEL1,
            aidDELEGATOR.name,
            aidDEL1,
            [aidDEL2],
            aidDELEGATOR,
            timestamp,
            true
        );
        const opList2 = await addEndRoleMultisig(
            clientDEL2,
            aidDELEGATOR.name,
            aidDEL2,
            [aidDEL1],
            aidDELEGATOR,
            timestamp
        );

        await Promise.all(opList1.map((op) => waitOperation(clientDEL1, op)));
        await Promise.all(opList2.map((op) => waitOperation(clientDEL2, op)));

        await waitAndMarkNotification(clientDEL1, '/multisig/rpy');

        [oobiDELbyDEL1, oobiDELbyDEL2] = await Promise.all([
            clientDEL1.oobis().get(aidDELEGATOR.name, 'agent'),
            clientDEL2.oobis().get(aidDELEGATOR.name, 'agent'),
        ]);
    }
    assert.equal(oobiDELbyDEL1.role, oobiDELbyDEL2.role);
    assert.equal(oobiDELbyDEL1.oobis[0], oobiDELbyDEL2.oobis[0]);

    // Delegatees resolve delegator's OOBI
    const oobiDELEGATOR = oobiDELbyDEL1.oobis[0].split('/agent/')[0];
    await Promise.all([
        getOrCreateContact(clientDEE1, aidDELEGATOR.name, oobiDELEGATOR),
        getOrCreateContact(clientDEE2, aidDELEGATOR.name, oobiDELEGATOR),
    ]);

    // Create multisig AID for the delegatee (delegated by delegator)
    let aidDEEbyDEE1, aidDEEbyDEE2: HabState;
    try {
        aidDEEbyDEE1 = await clientDEE1.identifiers().get('DELEGATEE');
        aidDEEbyDEE2 = await clientDEE2.identifiers().get('DELEGATEE');
    } catch {
        const rstates = [aidDEE1.state, aidDEE2.state];
        const states = rstates;

        const kargsMultisigAID: CreateIdentiferArgs = {
            algo: signify.Algos.group,
            isith: ['1/2', '1/2'],
            nsith: ['1/2', '1/2'],
            toad: kargsAID.toad,
            wits: kargsAID.wits,
            states: states,
            rstates: rstates,
            delpre: aidDELEGATOR.prefix,
        };

        kargsMultisigAID.mhab = aidDEE1;
        const multisigAIDOp1 = await createAIDMultisig(
            clientDEE1,
            aidDEE1,
            [aidDEE2],
            'DELEGATEE',
            kargsMultisigAID,
            true
        );

        kargsMultisigAID.mhab = aidDEE2;
        const multisigAIDOp2 = await createAIDMultisig(
            clientDEE2,
            aidDEE2,
            [aidDEE1],
            'DELEGATEE',
            kargsMultisigAID
        );

        const aidDELEGATEEPrefix = multisigAIDOp1.name.split('.')[1];
        assert.equal(multisigAIDOp2.name.split('.')[1], aidDELEGATEEPrefix);

        const anchor = {
            i: aidDELEGATEEPrefix,
            s: '0',
            d: aidDELEGATEEPrefix,
        };

        const ixnOp1 = await delegateMultisig(
            clientDEL1,
            aidDEL1,
            [aidDEL2],
            aidDELEGATOR,
            anchor,
            true
        );
        const ixnOp2 = await delegateMultisig(
            clientDEL2,
            aidDEL2,
            [aidDEL1],
            aidDELEGATOR,
            anchor
        );

        await Promise.all([
            waitOperation(clientDEL1, ixnOp1),
            waitOperation(clientDEL2, ixnOp2),
        ]);

        await waitAndMarkNotification(clientDEL1, '/multisig/ixn');

        // Delegatees query the delegator's key state
        const queryOp1 = await clientDEE1
            .keyStates()
            .query(aidDELEGATOR.prefix, '1');
        const queryOp2 = await clientDEE2
            .keyStates()
            .query(aidDELEGATOR.prefix, '1');

        await Promise.all([
            waitOperation(clientDEE1, multisigAIDOp1),
            waitOperation(clientDEE2, multisigAIDOp2),
            waitOperation(clientDEE1, queryOp1),
            waitOperation(clientDEE2, queryOp2),
        ]);

        await waitAndMarkNotification(clientDEE1, '/multisig/icp');

        aidDEEbyDEE1 = await clientDEE1.identifiers().get('DELEGATEE');
        aidDEEbyDEE2 = await clientDEE2.identifiers().get('DELEGATEE');
    }
    assert.equal(aidDEEbyDEE1.prefix, aidDEEbyDEE2.prefix);
    assert.equal(aidDEEbyDEE1.name, aidDEEbyDEE2.name);
    const aidDELEGATEE = aidDEEbyDEE1;

    // Individual delegatee members rotate their keys
    let rotResultDEE1 = await clientDEE1.identifiers().rotate('DEE1');
    let rotOpDEE1 = await rotResultDEE1.op();
    await waitOperation(clientDEE1, rotOpDEE1);

    let rotResultDEE2 = await clientDEE2.identifiers().rotate('DEE2');
    let rotOpDEE2 = await rotResultDEE2.op();
    await waitOperation(clientDEE2, rotOpDEE2);

    // Get updated AIDs after individual rotations
    const aidDEE1Updated = await clientDEE1.identifiers().get('DEE1');
    const aidDEE2Updated = await clientDEE2.identifiers().get('DEE2');

    // Update key states - all clients need to query all updated states
    await Promise.all([
        clientDEE1
            .keyStates()
            .query(aidDEE1Updated.prefix, aidDEE1Updated.state.s),
        clientDEE1
            .keyStates()
            .query(aidDEE2Updated.prefix, aidDEE2Updated.state.s),
        clientDEE2
            .keyStates()
            .query(aidDEE1Updated.prefix, aidDEE1Updated.state.s),
        clientDEE2
            .keyStates()
            .query(aidDEE2Updated.prefix, aidDEE2Updated.state.s),
    ]);

    // Prepare new states for multisig rotation
    const newStates = [aidDEE1Updated.state, aidDEE2Updated.state];
    const newRstates = newStates;

    // DEE1 initiates multisig rotation
    const { rotOp: rotOp1, rotSerder } = await rotateMultisig(
        clientDEE1,
        aidDEE1Updated,
        [aidDEE2Updated],
        aidDELEGATEE,
        newStates,
        newRstates,
        true
    );

    // DEE2 joins the rotation event
    const { rotOp: rotOp2 } = await rotateMultisig(
        clientDEE2,
        aidDEE2Updated,
        [aidDEE1Updated],
        aidDELEGATEE,
        newStates,
        newRstates
    );

    // Delegator anchors delegation rotation with an interaction event
    const rotAnchor = {
        i: aidDELEGATEE.prefix,
        s: '1',
        d: rotSerder.sad.d,
    };

    const ixnRotOp1 = await delegateMultisig(
        clientDEL1,
        aidDEL1,
        [aidDEL2],
        aidDELEGATOR,
        rotAnchor,
        true
    );
    const ixnRotOp2 = await delegateMultisig(
        clientDEL2,
        aidDEL2,
        [aidDEL1],
        aidDELEGATOR,
        rotAnchor
    );

    await Promise.all([
        waitOperation(clientDEL1, ixnRotOp1),
        waitOperation(clientDEL2, ixnRotOp2),
    ]);

    await waitAndMarkNotification(clientDEL1, '/multisig/ixn');

    // Delegatees query the delegator's key state after rotation anchoring
    const queryRotOp1 = await clientDEE1
        .keyStates()
        .query(aidDELEGATOR.prefix, '2');
    const queryRotOp2 = await clientDEE2
        .keyStates()
        .query(aidDELEGATOR.prefix, '2');

    await Promise.all([
        waitOperation(clientDEE1, queryRotOp1),
        waitOperation(clientDEE2, queryRotOp2),
    ]);

    // Wait for rotation operations to complete
    await Promise.all([
        waitOperation(clientDEE1, rotOp1),
        waitOperation(clientDEE2, rotOp2),
    ]);

    // Get final state after rotation
    const finalDelegatee1 = await clientDEE1.identifiers().get('DELEGATEE');
    const finalDelegatee2 = await clientDEE2.identifiers().get('DELEGATEE');

    // Verify rotation was successful
    assert.equal(finalDelegatee1.prefix, finalDelegatee2.prefix);
    assert.equal(finalDelegatee1.state.et, 'drt');
    assert.equal(finalDelegatee1.state.di, aidDELEGATOR.prefix);
}, 400000);

export async function rotateMultisig(
    client: SignifyClient,
    aid: HabState,
    otherMembersAIDs: HabState[],
    multisigAID: HabState,
    newStates: any[],
    newRstates: any[],
    isInitiator: boolean = false
) {
    if (!isInitiator) {
        const msgSaid = await waitAndMarkNotification(client, '/multisig/rot');

        const res = await client.groups().getRequest(msgSaid);
        const exn = res[0].exn;
        if (!('a' in exn) || !exn.a) {
            throw new Error('exn.a is missing from the group rotation request');
        }
    }

    const rotationResult = await client
        .identifiers()
        .rotate(multisigAID.name, { states: newStates, rstates: newRstates });
    const rotOp = await rotationResult.op();
    const rotSerder = rotationResult.serder;
    const rotSigs = rotationResult.sigs;
    const rotSigers = rotSigs.map((sig) => new signify.Siger({ qb64: sig }));

    const rotIms = signify.d(signify.messagize(rotSerder, rotSigers));
    const rotAtc = rotIms.substring(rotSerder.size);
    const rotEmbeds = {
        rot: [rotSerder, rotAtc],
    };

    const rotSmids = newStates.map((state: any) => state.i);
    const rotRecp = otherMembersAIDs.map((aid) => aid.prefix);

    const exchangeType = isInitiator ? '/multisig/rot' : '/multisig/ixn';

    await client
        .exchanges()
        .send(
            aid.name,
            'multisig',
            aid,
            exchangeType,
            { gid: rotSerder.pre, smids: rotSmids, rmids: rotSmids },
            rotEmbeds,
            rotRecp
        );

    return { rotOp, rotSerder };
}
