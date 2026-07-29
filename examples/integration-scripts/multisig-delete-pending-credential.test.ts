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

const { vleiServerUrl, witnessIds } = resolveEnvironment();

const MEMBER_1 = 'delete-activity-member-1';
const MEMBER_2 = 'delete-activity-member-2';
const GROUP = 'delete-activity-group';
const REGISTRY = 'delete-activity-registry';

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const SCHEMA_BASE_URL = process.env.SCHEMA_BASE_URL ?? vleiServerUrl;
const QVI_SCHEMA_URL = `${SCHEMA_BASE_URL}/oobi/${QVI_SCHEMA_SAID}`;
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

async function issueCredential(
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

test('members manually delete a pending credential by activity SAID', async () => {
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
    const aliceIssuance = await issueCredential(
        alice,
        aliceAid,
        bobAid,
        aliceGroup,
        credential,
        preIssuanceAnchor,
        `issuance-${Date.now()}`
    );
    await waitAndMarkNotification(bob, '/multisig/iss');

    assert.equal(aliceIssuance.anchor.sn, preIssuanceAnchor.sn + 1);
    assert.deepEqual(await getLatestAnchor(alice, GROUP), aliceIssuance.anchor);

    const aliceMemberRotation = await alice.identifiers().rotate(MEMBER_1);
    await waitOperation(alice, await aliceMemberRotation.op());
    const rotatedAliceAid = await alice.identifiers().get(MEMBER_1);

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

    const activitySaid = aliceIssuance.anchor.d;
    const [aliceDeletion, bobDeletion] = await Promise.all([
        alice.credentials().deletePending(GROUP, activitySaid),
        bob.credentials().deletePending(GROUP, activitySaid),
    ]);

    assert.ok(aliceDeletion.kelEvents.includes(activitySaid));
    assert.ok(bobDeletion.kelEvents.includes(activitySaid));
    assert.equal(aliceDeletion.telEvents.length, 1);
    assert.ok(
        aliceDeletion.credentialEscrows.includes(aliceIssuance.credentialSaid)
    );
    assert.ok(
        bobDeletion.credentialEscrows.includes(aliceIssuance.credentialSaid)
    );

    const [aliceLatest, bobLatest] = await Promise.all([
        getLatestAnchor(alice, GROUP),
        getLatestAnchor(bob, GROUP),
    ]);
    for (const latest of [aliceLatest, bobLatest]) {
        assert.deepEqual(
            latest,
            preIssuanceAnchor,
            'manual deletion must free N+1 for the group rotation'
        );
    }

    let retryAttempted = false;
    if (!bobStatus.inProgress) {
        retryAttempted = true;
        await bob.credentials().issue(GROUP, credential, preIssuanceAnchor);
    }
    assert.equal(retryAttempted, false);

    await assert.rejects(
        bob.credentials().deletePending(GROUP, activitySaid),
        /DELETE .*\/credentials\/pending\/.* - 404 Not Found/
    );
}, 360000);
