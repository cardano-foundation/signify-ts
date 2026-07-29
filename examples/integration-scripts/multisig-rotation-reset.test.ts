import { strict as assert } from 'assert';
import signify, {
    Algos,
    AnchorPoint,
    CredentialData,
    CredentialSubject,
    CreateIdentiferArgs,
    HabState,
    Siger,
    b,
    d,
    messagize,
    randomNonce,
    serializeACDCAttachment,
    serializeIssExnAttachment,
} from 'signify-ts';
import { createAIDMultisig } from './utils/multisig-utils';
import { resolveEnvironment } from './utils/resolve-env';
import {
    createTimestamp,
    getOrCreateAID,
    getOrCreateClients,
    resolveOobi,
    waitAndMarkNotification,
    waitOperation,
} from './utils/test-util';

const { witnessIds } = resolveEnvironment();

const MEMBER_1 = 'wallet-issuance-reset-member-1';
const MEMBER_2 = 'wallet-issuance-reset-member-2';
const GROUP = 'wallet-issuance-reset-group';
const REGISTRY = 'wallet-issuance-reset-registry';

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const QVI_SCHEMA_URL = `http://127.0.0.1:3001/oobi/${QVI_SCHEMA_SAID}`;
const CREDENTIAL_ISSUEE_AID = 'EBgew7O4yp8SBle0FU-wwN3GtnaroI0BQfBGAj33QiIG';

async function getLatestAnchor(
    client: signify.SignifyClient,
    name: string
): Promise<AnchorPoint> {
    const latest = await client.identifiers().getLatestEvent(name);
    return {
        sn: parseInt(latest.s, 16),
        d: latest.d,
    };
}

async function createRegistryLikeWallet(
    client: signify.SignifyClient,
    memberAid: HabState,
    otherMemberAid: HabState,
    group: HabState,
    nonce: string,
    anchorPoint: AnchorPoint,
    correlationId: string
) {
    const result = await client.registries().create({
        name: group.name,
        registryName: REGISTRY,
        nonce,
        anchorPoint,
    });
    const op = await result.op();

    const sigers = result.sigs.map((sig: string) => new Siger({ qb64: sig }));
    const message = d(messagize(result.serder, sigers));
    const anchorAttachment = message.substring(result.serder.size);
    const registryAttachment = d(serializeIssExnAttachment(result.serder));

    await client.exchanges().send(
        memberAid.name,
        REGISTRY,
        memberAid,
        '/multisig/vcp',
        {
            gid: group.prefix,
            cid: correlationId,
        },
        {
            vcp: [result.regser, registryAttachment],
            anc: [result.serder, anchorAttachment],
        },
        [otherMemberAid.prefix]
    );

    return {
        op,
        registryKey: result.regser.pre,
        anchor: {
            sn: parseInt(result.serder.ked.s, 16),
            d: result.serder.ked.d,
        } as AnchorPoint,
    };
}

async function issueCredentialLikeWallet(
    client: signify.SignifyClient,
    memberAid: HabState,
    otherMemberAid: HabState,
    group: HabState,
    credential: CredentialData,
    anchorPoint: AnchorPoint,
    correlationId: string
) {
    const result = await client
        .credentials()
        .issue(group.name, credential, anchorPoint);

    const keeper = client.manager!.get(group);
    const signatures = await keeper.sign(b(result.anc.raw));
    const sigers = signatures.map((sig: string) => new Siger({ qb64: sig }));
    const message = d(messagize(result.anc, sigers));
    const anchorAttachment = message.substring(result.anc.size);
    const credentialAttachment = d(serializeACDCAttachment(result.iss));
    const issuanceAttachment = d(serializeIssExnAttachment(result.anc));

    await client.exchanges().send(
        memberAid.name,
        'multisig',
        memberAid,
        '/multisig/iss',
        {
            gid: group.prefix,
            cid: correlationId,
        },
        {
            acdc: [result.acdc, credentialAttachment],
            iss: [result.iss, issuanceAttachment],
            anc: [result.anc, anchorAttachment],
        },
        [otherMemberAid.prefix]
    );

    return {
        op: result.op,
        credentialSaid: result.acdc.ked.d,
        anchor: {
            sn: parseInt(result.anc.ked.s, 16),
            d: result.anc.ked.d,
        } as AnchorPoint,
    };
}

async function sendMemberRotationSignal(
    client: signify.SignifyClient,
    memberAid: HabState,
    otherMemberAid: HabState,
    group: HabState
) {
    await client.exchanges().send(
        memberAid.name,
        'member-rotation',
        memberAid,
        '/multisig/member/rot',
        {
            gid: group.prefix,
            sn: memberAid.state.s,
            gsn: group.state.ee.s,
        },
        {},
        [otherMemberAid.prefix]
    );
}

async function getGroupRotationStatus(
    client: signify.SignifyClient,
    groupName: string
) {
    const [group, members] = await Promise.all([
        client.identifiers().get(groupName),
        client.identifiers().members(groupName),
    ]);
    const memberStates = await client
        .keyStates()
        .list(members.signing.map((member: { aid: string }) => member.aid));
    const rotatedMembers = memberStates.filter(
        (state: { i: string; k: string[] }) =>
            !group.state.k.includes(state.k[0])
    );

    return {
        inProgress: rotatedMembers.length > 0,
        rotatedMembers: rotatedMembers.map((state: { i: string }) => state.i),
    };
}

test('member rotation resets a wallet-style partial credential issuance', async () => {
    await signify.ready();
    const [alice, bob] = await getOrCreateClients(2);

    const memberArgs: CreateIdentiferArgs = {
        toad: witnessIds.length,
        wits: witnessIds,
    };
    const [aliceAid, bobAid] = await Promise.all([
        getOrCreateAID(alice, MEMBER_1, memberArgs),
        getOrCreateAID(bob, MEMBER_2, memberArgs),
    ]);

    const [aliceOobi, bobOobi] = await Promise.all([
        alice.oobis().get(MEMBER_1, 'agent'),
        bob.oobis().get(MEMBER_2, 'agent'),
    ]);
    await Promise.all([
        resolveOobi(alice, bobOobi.oobis[0], MEMBER_2),
        resolveOobi(bob, aliceOobi.oobis[0], MEMBER_1),
        resolveOobi(alice, QVI_SCHEMA_URL),
        resolveOobi(bob, QVI_SCHEMA_URL),
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

    // Complete registry creation before the race. This matches the wallet's
    // common issuance path when ensureRegistry finds an existing registry.
    const registryBase = await getLatestAnchor(alice, GROUP);
    const registryNonce = randomNonce();
    const registryCorrelationId = `registry-${Date.now()}`;
    const aliceRegistry = await createRegistryLikeWallet(
        alice,
        aliceAid,
        bobAid,
        aliceGroup,
        registryNonce,
        registryBase,
        registryCorrelationId
    );
    await waitAndMarkNotification(bob, '/multisig/vcp');
    const bobRegistry = await createRegistryLikeWallet(
        bob,
        bobAid,
        aliceAid,
        bobGroup,
        registryNonce,
        registryBase,
        registryCorrelationId
    );
    assert.equal(bobRegistry.registryKey, aliceRegistry.registryKey);
    assert.deepEqual(bobRegistry.anchor, aliceRegistry.anchor);
    await Promise.all([
        waitOperation(alice, aliceRegistry.op),
        waitOperation(bob, bobRegistry.op),
    ]);

    // Alice now follows issuanceService: read the latest KEL event, construct
    // the ACDC/TEL issue plus its ixn anchor, and send /multisig/iss with cid.
    const preIssuanceAnchor = await getLatestAnchor(alice, GROUP);
    assert.deepEqual(preIssuanceAnchor, aliceRegistry.anchor);

    const credential: CredentialData = {
        i: aliceGroup.prefix,
        ri: aliceRegistry.registryKey,
        s: QVI_SCHEMA_SAID,
        a: {
            i: CREDENTIAL_ISSUEE_AID,
            dt: createTimestamp(),
            LEI: '254900OPPU84GM83MG36',
        } as CredentialSubject,
    };
    const issuanceCorrelationId = `issuance-${Date.now()}`;
    const aliceIssuance = await issueCredentialLikeWallet(
        alice,
        aliceAid,
        bobAid,
        aliceGroup,
        credential,
        preIssuanceAnchor,
        issuanceCorrelationId
    );
    await waitAndMarkNotification(bob, '/multisig/iss');

    assert.equal(
        aliceIssuance.anchor.sn,
        preIssuanceAnchor.sn + 1,
        'the partial issuance must reserve the next group KEL sequence number'
    );
    const latestWithPartialIssuance = await getLatestAnchor(alice, GROUP);
    assert.deepEqual(latestWithPartialIssuance, aliceIssuance.anchor);

    // Alice rotates her member AID. This is the state transition used by the
    // wallet's getGroupRotationStatus; no extra notification is needed to
    // decide that the group has entered rotation.
    const aliceMemberRotation = await alice.identifiers().rotate(MEMBER_1);
    await waitOperation(alice, await aliceMemberRotation.op());
    const rotatedAliceAid = await alice.identifiers().get(MEMBER_1);

    // Make the new member key state available to Bob, then send the existing
    // member-rotation signal used by the wallet.
    const aliceStateQuery = await bob
        .keyStates()
        .query(rotatedAliceAid.prefix, rotatedAliceAid.state.s);
    await waitOperation(bob, aliceStateQuery);
    await sendMemberRotationSignal(alice, rotatedAliceAid, bobAid, aliceGroup);
    await waitAndMarkNotification(bob, '/exn/multisig/member/rot');

    const [aliceStatus, bobStatus] = await Promise.all([
        getGroupRotationStatus(alice, GROUP),
        getGroupRotationStatus(bob, GROUP),
    ]);
    assert.equal(aliceStatus.inProgress, true);
    assert.equal(bobStatus.inProgress, true);
    assert.equal(aliceStatus.rotatedMembers.length, 1);
    assert.equal(bobStatus.rotatedMembers.length, 1);
    assert.equal(aliceStatus.rotatedMembers[0], aliceAid.prefix);
    assert.equal(bobStatus.rotatedMembers[0], aliceAid.prefix);

    // The accepted group establishment SAID identifies the rotation round for
    // every member and changes after each committed group rotation.
    const rotationId = aliceGroup.state.ee.d;
    const [aliceReset, bobReset] = await Promise.all([
        alice.identifiers().resetPendingActivities(GROUP, rotationId),
        bob.identifiers().resetPendingActivities(GROUP, rotationId),
    ]);
    assert.equal(aliceReset.alreadyReset, false);
    assert.equal(bobReset.alreadyReset, false);
    assert.ok(aliceReset.kelEvents.includes(aliceIssuance.anchor.d));
    assert.ok(bobReset.kelEvents.includes(aliceIssuance.anchor.d));
    assert.equal(aliceReset.telEvents.length, 1);
    assert.ok(
        aliceReset.credentialEscrows.includes(aliceIssuance.credentialSaid)
    );
    assert.ok(
        bobReset.credentialEscrows.includes(aliceIssuance.credentialSaid)
    );

    const [aliceLatestAfterReset, bobLatestAfterReset] = await Promise.all([
        getLatestAnchor(alice, GROUP),
        getLatestAnchor(bob, GROUP),
    ]);
    for (const latest of [aliceLatestAfterReset, bobLatestAfterReset]) {
        assert.deepEqual(
            latest,
            preIssuanceAnchor,
            'resetting the partial issuance must free N+1 for rotation'
        );
    }

    // This models Bob's reconnect handler. The edge checks rotation state
    // before replaying queued work and skips the issuance while rotating.
    let retryAttempted = false;
    if (!bobStatus.inProgress) {
        retryAttempted = true;
        await bob.credentials().issue(GROUP, credential, preIssuanceAnchor);
    }
    assert.equal(retryAttempted, false);

    const bobLatest = await getLatestAnchor(bob, GROUP);
    assert.deepEqual(
        bobLatest,
        preIssuanceAnchor,
        'a skipped retry must not alter Bob’s pending KEL state'
    );

    const repeated = await bob
        .identifiers()
        .resetPendingActivities(GROUP, rotationId);
    assert.equal(repeated.alreadyReset, true);

    assert.ok(aliceIssuance.credentialSaid);
}, 360000);
