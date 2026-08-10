import { strict as assert } from 'assert';
import signify, {
    AnchorPoint,
    CreateIdentiferArgs,
    CredentialData,
    CredentialSubject,
    HabState,
    SignifyClient,
    randomNonce,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    createTimestamp,
    getOrCreateAID,
    getEndRoles,
    getOrCreateClients,
    resolveOobi,
    waitAndMarkNotification,
    waitOperation,
} from './utils/test-util';
import {
    addEndRoleMultisig,
    createAIDMultisig,
    createRegistryMultisig,
    issueCredentialMultisig,
} from './utils/multisig-utils';
import { retry } from './utils/retry';
import { step } from './utils/test-step';

const { vleiServerUrl, witnessIds } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const QVI_SCHEMA_URL = `${vleiServerUrl}/oobi/${QVI_SCHEMA_SAID}`;
const CREDENTIAL_ISSUEE_AID = 'EBgew7O4yp8SBle0FU-wwN3GtnaroI0BQfBGAj33QiIG';

test('a partially signed registry creation superseded by a rotation does not block the next one', async () => {
    let group = await step('create a 2 of 2 group', async () =>
        createMultisigGroup()
    );

    const nonce = randomNonce();
    const stuck = await step(
        `M1 creates a registry at sn: ${nextSn(group)}, M2 does not join`,
        async () =>
            createRegistryMultisig(
                group.client1,
                group.member1,
                [group.member2],
                group.aid,
                'reg',
                nonce,
                true
            )
    );

    group = await step(
        `group does a full rotation to sn: ${nextSn(group)}`,
        async () => {
            const rotated = await rotateMultisigGroup(group);
            assertRotationSuperseded(rotated, stuck.ancSn);
            await assertStillPending(rotated.client1, stuck.op);
            return rotated;
        }
    );

    await step(
        `create the registry again at the new sn: ${nextSn(group)}, M2 joins`,
        async () => {
            const retry1 = await createRegistryMultisig(
                group.client1,
                group.member1,
                [group.member2],
                group.aid,
                'regRetry',
                nonce,
                true
            );
            const retry2 = await createRegistryMultisig(
                group.client2,
                group.member2,
                [group.member1],
                group.aid,
                'regRetry',
                nonce,
                false
            );
            assert.equal(
                retry1.regk,
                stuck.regk,
                'retry must target the same registry'
            );
            await Promise.all([
                waitOperation(group.client1, retry1.op),
                waitOperation(group.client2, retry2.op),
            ]);
        }
    );

    await step('the registry creation succeeded', async () => {
        const registries = await group.client1.registries().list('group');
        assert(
            registries.some((r: { regk: string }) => r.regk === stuck.regk),
            'the re-actioned registry should exist'
        );
    });
}, 600000);

test('a partially signed credential issuance superseded by a rotation does not block the next activity', async () => {
    let group = await step('create a 2 of 2 group', async () =>
        createMultisigGroup()
    );

    const [registry] = await step(
        `create a registry at sn: ${nextSn(group)}`,
        async () => createRegistryAsGroup(group, 'reg')
    );
    group.aid = await group.client1.identifiers().get('group');
    await Promise.all([
        resolveOobi(group.client1, QVI_SCHEMA_URL),
        resolveOobi(group.client2, QVI_SCHEMA_URL),
    ]);

    const credData: CredentialData = {
        i: group.aid.prefix,
        ri: registry.regk,
        s: QVI_SCHEMA_SAID,
        a: {
            i: CREDENTIAL_ISSUEE_AID,
            dt: createTimestamp(),
            LEI: '254900OPPU84GM83MG36',
        } as CredentialSubject,
    };

    const stuck = await step(
        `M1 issues a credential at sn: ${nextSn(group)}, M2 does not join`,
        async () =>
            issueCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                'group',
                credData,
                true
            )
    );

    group = await step(
        `group does a full rotation to sn: ${nextSn(group)}`,
        async () => {
            const rotated = await rotateMultisigGroup(group);
            assertRotationSuperseded(rotated, stuck.anc.sn);
            await assertStillPending(rotated.client1, stuck.op);
            return rotated;
        }
    );

    await step(
        `a fully signed registry creation at sn: ${nextSn(
            group
        )} is not blocked`,
        async () => {
            await createRegistryAsGroup(group, 'afterRotation');
            group.aid = await group.client1.identifiers().get('group');
        }
    );

    const credSaid = await step(
        `issue the credential again at the new sn: ${nextSn(group)}, M2 joins`,
        async () => {
            const retry1 = await issueCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                'group',
                credData,
                true
            );
            const retry2 = await issueCredentialMultisig(
                group.client2,
                group.member2,
                [group.member1],
                'group',
                credData,
                false
            );
            const [op1] = await Promise.all([
                waitOperation(group.client1, retry1.op),
                waitOperation(group.client2, retry2.op),
            ]);
            return op1.name.split('.').slice(1).join('.');
        }
    );

    await step('the issuance succeeded', async () => {
        const cred = await retry(async () =>
            group.client1.credentials().get(credSaid)
        );
        assert.equal(cred.status.s, '0', 'credential should be active');
    });
}, 600000);

test('a partially signed credential revocation superseded by a rotation does not block the next activity', async () => {
    let group = await step('create a 2 of 2 group', async () =>
        createMultisigGroup()
    );

    const [registry] = await step(
        `create a registry at sn: ${nextSn(group)}`,
        async () => createRegistryAsGroup(group, 'reg')
    );
    group.aid = await group.client1.identifiers().get('group');
    await Promise.all([
        resolveOobi(group.client1, QVI_SCHEMA_URL),
        resolveOobi(group.client2, QVI_SCHEMA_URL),
    ]);

    const credData: CredentialData = {
        i: group.aid.prefix,
        ri: registry.regk,
        s: QVI_SCHEMA_SAID,
        a: {
            i: CREDENTIAL_ISSUEE_AID,
            dt: createTimestamp(),
            LEI: '254900OPPU84GM83MG36',
        } as CredentialSubject,
    };

    const credSaid = await step(
        `issue a credential to revoke at sn: ${nextSn(group)}`,
        async () => {
            const issued1 = await issueCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                'group',
                credData,
                true
            );
            const issued2 = await issueCredentialMultisig(
                group.client2,
                group.member2,
                [group.member1],
                'group',
                credData,
                false
            );
            const [op1] = await Promise.all([
                waitOperation(group.client1, issued1.op),
                waitOperation(group.client2, issued2.op),
            ]);
            const said = op1.name.split('.').slice(1).join('.');
            await retry(async () => group.client1.credentials().get(said));
            group.aid = await group.client1.identifiers().get('group');
            return said;
        }
    );

    const stuck = await step(
        `M1 revokes the credential at sn: ${nextSn(group)}, M2 does not join`,
        async () =>
            revokeCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                'group',
                credSaid,
                true,
                createTimestamp()
            )
    );
    const stuckSn = parseInt(stuck.anc.ked['s'] as string, 16);

    group = await step(
        `group does a full rotation to sn: ${nextSn(group)}`,
        async () => {
            const rotated = await rotateMultisigGroup(group);
            assertRotationSuperseded(rotated, stuckSn);

            // revocation has no operation of its own -- it returns the anchoring group op,
            // which the rotation completes at that same sn -- so read the credential
            const stillActive = await rotated.client1
                .credentials()
                .get(credSaid);
            assert.equal(
                stillActive.status.s,
                '0',
                'the half-signed revocation must not have applied'
            );
            return rotated;
        }
    );

    await step(
        `a fully signed registry creation at sn: ${nextSn(
            group
        )} is not blocked`,
        async () => {
            await createRegistryAsGroup(group, 'afterRotation');
            group.aid = await group.client1.identifiers().get('group');
        }
    );

    await step(
        `revoke the credential again at the new sn: ${nextSn(group)}, M2 joins`,
        async () => {
            const timestamp = createTimestamp();
            const retry1 = await revokeCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                'group',
                credSaid,
                true,
                timestamp
            );
            const retry2 = await revokeCredentialMultisig(
                group.client2,
                group.member2,
                [group.member1],
                'group',
                credSaid,
                false,
                timestamp
            );
            await Promise.all([
                waitOperation(group.client1, retry1.op),
                waitOperation(group.client2, retry2.op),
            ]);
        }
    );

    await step('the revocation succeeded', async () => {
        const after = await group.client1.credentials().get(credSaid);
        assert.equal(after.status.s, '1', 'credential should be revoked');
    });
}, 600000);

test('a partially signed exchange message from an old sn does not block a fully signed one after a rotation', async () => {
    let group = await step('create a 2 of 2 group', async () =>
        createMultisigGroup()
    );

    const [issuerClient] = await getOrCreateClients(1);
    const issuer = await step(
        'set up an issuer that can reach both members',
        async () => {
            const aid = await getOrCreateAID(issuerClient, 'issuer', {
                toad: witnessIds.length,
                wits: witnessIds,
            });

            const advertised = await group.client1
                .oobis()
                .get('group', 'agent');
            const oobiBase = advertised.oobis[0].split('/oobi/')[0];
            const roles = await getEndRoles(group.client1, 'group', 'agent');
            for (const role of roles) {
                await resolveOobi(
                    issuerClient,
                    `${oobiBase}/oobi/${role.cid}/agent/${role.eid}`
                );
            }

            await Promise.all([
                resolveOobi(issuerClient, QVI_SCHEMA_URL),
                resolveOobi(group.client1, QVI_SCHEMA_URL),
                resolveOobi(group.client2, QVI_SCHEMA_URL),
            ]);
            const issuerOobi = await issuerClient
                .oobis()
                .get('issuer', 'agent');
            await Promise.all([
                resolveOobi(group.client1, issuerOobi.oobis[0], 'issuer'),
                resolveOobi(group.client2, issuerOobi.oobis[0], 'issuer'),
            ]);
            return aid;
        }
    );

    const acdcSaid = await step(
        'issuer grants a credential to the group',
        async () => {
            const created = await issuerClient
                .registries()
                .create({ name: 'issuer', registryName: 'issuerReg' });
            await waitOperation(issuerClient, await created.op());
            const [issuerRegistry] = await issuerClient
                .registries()
                .list('issuer');

            const issued = await issuerClient.credentials().issue('issuer', {
                i: issuer.prefix,
                ri: issuerRegistry.regk,
                s: QVI_SCHEMA_SAID,
                a: {
                    i: group.aid.prefix,
                    dt: createTimestamp(),
                    LEI: '254900OPPU84GM83MG36',
                } as CredentialSubject,
            });
            await waitOperation(issuerClient, issued.op);

            const [grant, grantSigs, grantEnd] = await issuerClient
                .ipex()
                .grant({
                    senderName: 'issuer',
                    recipient: group.aid.prefix,
                    datetime: createTimestamp(),
                    acdc: issued.acdc,
                    anc: issued.anc,
                    iss: issued.iss,
                });
            await waitOperation(
                issuerClient,
                await issuerClient
                    .ipex()
                    .submitGrant('issuer', grant, grantSigs, grantEnd, [
                        group.aid.prefix,
                    ])
            );
            return issued.acdc.ked['d'] as string;
        }
    );

    const grantSaid = await waitAndMarkNotification(
        group.client1,
        '/exn/ipex/grant'
    );

    const stuck = await step(
        `M1 signs the admit at sn: ${parseInt(
            group.aid.state.s,
            16
        )}, M2 does not sign`,
        async () =>
            admitCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                issuer.prefix,
                grantSaid,
                createTimestamp()
            )
    );
    const stuckSn = parseInt(group.aid.state.s, 16);

    await step('member 2 receives the same grant', async () => {
        // member 2 only learns of it from member 1's /multisig/exn
        const seen = await retry(
            async () =>
                waitAndMarkNotification(group.client2, '/exn/ipex/grant'),
            { timeout: 60000 }
        );
        assert.equal(seen, grantSaid, 'both members see the same grant');
    });

    group = await step(
        `group does a full rotation to sn: ${nextSn(group)}`,
        async () => {
            const rotated = await rotateMultisigGroup(group);
            assertKeyStateAdvanced(rotated, stuckSn);
            await assertStillPending(rotated.client1, stuck.op);
            return rotated;
        }
    );

    await step(
        `sign the admit again on the new keys at sn: ${parseInt(
            group.aid.state.s,
            16
        )}, M2 joins`,
        async () => {
            // one shared timestamp so both members build the identical exn
            const timestamp = createTimestamp();
            const admit1 = await admitCredentialMultisig(
                group.client1,
                group.member1,
                [group.member2],
                issuer.prefix,
                grantSaid,
                timestamp
            );
            const admit2 = await admitCredentialMultisig(
                group.client2,
                group.member2,
                [group.member1],
                issuer.prefix,
                grantSaid,
                timestamp
            );
            await Promise.all([
                waitOperation(group.client1, admit1.op),
                waitOperation(group.client2, admit2.op),
            ]);
        }
    );

    await step('the admit succeeded', async () => {
        const held = await retry(async () =>
            group.client1.credentials().get(acdcSaid)
        );
        assert.equal(
            held.sad.d,
            acdcSaid,
            'group should hold the admitted credential'
        );
    });
}, 600000);

/** Admit a granted credential as the group, without consuming a notification. */
async function admitCredentialMultisig(
    client: SignifyClient,
    aid: HabState,
    otherMembersAIDs: HabState[],
    issuerPrefix: string,
    grantSaid: string,
    timestamp: string
) {
    const groupAid = await client.identifiers().get('group');

    const [admit, sigs, end] = await client.ipex().admit({
        senderName: 'group',
        message: '',
        grantSaid,
        recipient: issuerPrefix,
        datetime: timestamp,
    });
    const op = await client
        .ipex()
        .submitAdmit('group', admit, sigs, end, [issuerPrefix]);

    const seal = [
        'SealEvent',
        {
            i: groupAid.prefix,
            s: groupAid.state['ee']['s'],
            d: groupAid.state['ee']['d'],
        },
    ];
    const sigers = sigs.map((sig: string) => new signify.Siger({ qb64: sig }));
    const ims = signify.d(signify.messagize(admit, sigers, seal));
    const atc = ims.substring(admit.size) + end;

    await client.exchanges().send(
        aid.name,
        'multisig',
        aid,
        '/multisig/exn',
        { gid: groupAid.prefix },
        { exn: [admit, atc] },
        otherMembersAIDs.map((m) => m.prefix)
    );

    return { admit, op };
}

interface MultisigGroup {
    client1: SignifyClient;
    client2: SignifyClient;
    member1: HabState;
    member2: HabState;
    aid: HabState;
}

async function createMultisigGroup(): Promise<MultisigGroup> {
    const [client1, client2] = await getOrCreateClients(2);

    const kargsWitnessed: CreateIdentiferArgs = {
        toad: witnessIds.length,
        wits: witnessIds,
    };
    const [member1, member2] = await Promise.all([
        getOrCreateAID(client1, 'member1', kargsWitnessed),
        getOrCreateAID(client2, 'member2', kargsWitnessed),
    ]);

    const [oobi1, oobi2] = await Promise.all([
        client1.oobis().get('member1', 'agent'),
        client2.oobis().get('member2', 'agent'),
    ]);
    await Promise.all([
        resolveOobi(client1, oobi2.oobis[0], 'member2'),
        resolveOobi(client2, oobi1.oobis[0], 'member1'),
    ]);

    const rstates = [member1.state, member2.state];
    const kargsMultisig: CreateIdentiferArgs = {
        algo: signify.Algos.group,
        isith: ['1/2', '1/2'],
        nsith: ['1/2', '1/2'],
        toad: kargsWitnessed.toad,
        wits: kargsWitnessed.wits,
        states: rstates,
        rstates,
    };

    kargsMultisig.mhab = member1;
    const icpOp1 = await createAIDMultisig(
        client1,
        member1,
        [member2],
        'group',
        kargsMultisig,
        true
    );
    kargsMultisig.mhab = member2;
    const icpOp2 = await createAIDMultisig(
        client2,
        member2,
        [member1],
        'group',
        kargsMultisig
    );
    await Promise.all([
        waitOperation(client1, icpOp1),
        waitOperation(client2, icpOp2),
    ]);

    const aid = await client1.identifiers().get('group');

    const timestamp = createTimestamp();
    const endRoleOps1 = await addEndRoleMultisig(
        client1,
        aid.name,
        member1,
        [member2],
        aid,
        timestamp,
        true
    );
    const endRoleOps2 = await addEndRoleMultisig(
        client2,
        aid.name,
        member2,
        [member1],
        aid,
        timestamp
    );
    await Promise.all([
        ...endRoleOps1.map((op) => waitOperation(client1, op)),
        ...endRoleOps2.map((op) => waitOperation(client2, op)),
    ]);

    return { client1, client2, member1, member2, aid };
}

/** Both member AIDs rotate, then the group rotates onto their new key states. */
async function rotateMultisigGroup(
    group: MultisigGroup
): Promise<MultisigGroup> {
    const rot1 = await group.client1.identifiers().rotate('member1');
    await waitOperation(group.client1, await rot1.op());
    const member1 = await group.client1.identifiers().get('member1');

    const rot2 = await group.client2.identifiers().rotate('member2');
    await waitOperation(group.client2, await rot2.op());
    const member2 = await group.client2.identifiers().get('member2');

    let query = await group.client1
        .keyStates()
        .query(member2.prefix, member2.state.s);
    const state2 = (await waitOperation(group.client1, query))['response'];
    query = await group.client2
        .keyStates()
        .query(member1.prefix, member1.state.s);
    const state1 = (await waitOperation(group.client2, query))['response'];

    const states = [state1, state2];
    const smids = states.map((state: { i: string }) => state.i);

    const event1 = await group.client1
        .identifiers()
        .rotate('group', { states, rstates: states });
    const op1 = await event1.op();
    let serder = event1.serder;
    let sigers = event1.sigs.map((sig) => new signify.Siger({ qb64: sig }));
    let atc = signify
        .d(signify.messagize(serder, sigers))
        .substring(serder.size);

    await group.client1
        .exchanges()
        .send(
            'member1',
            'multisig',
            member1,
            '/multisig/rot',
            { gid: serder.pre, smids, rmids: smids },
            { rot: [serder, atc] },
            [member2.prefix]
        );

    await waitAndMarkNotification(group.client2, '/multisig/rot');

    const event2 = await group.client2
        .identifiers()
        .rotate('group', { states, rstates: states });
    const op2 = await event2.op();
    serder = event2.serder;
    sigers = event2.sigs.map((sig) => new signify.Siger({ qb64: sig }));
    atc = signify.d(signify.messagize(serder, sigers)).substring(serder.size);

    await group.client2
        .exchanges()
        .send(
            'member2',
            'multisig',
            member2,
            '/multisig/ixn',
            { gid: serder.pre, smids, rmids: smids },
            { rot: [serder, atc] },
            [member1.prefix]
        );

    await Promise.all([
        waitOperation(group.client1, op1),
        waitOperation(group.client2, op2),
    ]);

    const aid = await group.client1.identifiers().get('group');
    return { ...group, member1, member2, aid };
}

async function createRegistryAsGroup(group: MultisigGroup, name: string) {
    const nonce = randomNonce();
    const first = await createRegistryMultisig(
        group.client1,
        group.member1,
        [group.member2],
        group.aid,
        name,
        nonce,
        true
    );
    const second = await createRegistryMultisig(
        group.client2,
        group.member2,
        [group.member1],
        group.aid,
        name,
        nonce,
        false
    );
    await Promise.all([
        waitOperation(group.client1, first.op),
        waitOperation(group.client2, second.op),
    ]);
    return [first, second];
}

/** Revoke a credential from a group, mirroring issueCredentialMultisig. */
async function revokeCredentialMultisig(
    client: SignifyClient,
    aid: HabState,
    otherMembersAIDs: HabState[],
    multisigAIDName: string,
    credSaid: string,
    isInitiator: boolean = false,
    datetime?: string,
    anchorPoint?: AnchorPoint
) {
    if (!isInitiator) await waitAndMarkNotification(client, '/multisig/rev');

    const revResult = await client
        .credentials()
        .revoke(multisigAIDName, credSaid, datetime, anchorPoint);

    const multisigAID = await client.identifiers().get(multisigAIDName);
    const keeper = client.manager!.get(multisigAID);
    const sigs = await keeper.sign(signify.b(revResult.anc.raw));
    const sigers = sigs.map((sig: string) => new signify.Siger({ qb64: sig }));
    const ims = signify.d(signify.messagize(revResult.anc, sigers));
    const atc = ims.substring(revResult.anc.size);

    await client.exchanges().send(
        aid.name,
        'multisig',
        aid,
        '/multisig/rev',
        { gid: multisigAID.prefix },
        { iss: [revResult.rev, ''], anc: [revResult.anc, atc] },
        otherMembersAIDs.map((member) => member.prefix)
    );

    return { op: revResult.op, anc: revResult.anc };
}

/** The sn a group activity submitted now will anchor at. */
function nextSn(group: MultisigGroup) {
    return parseInt(group.aid.state.s, 16) + 1;
}

/** The rotation must land on the sn the stuck activity anchored to, or it supersedes nothing. */
function assertRotationSuperseded(group: MultisigGroup, anchoredSn: number) {
    const rotatedSn = parseInt(group.aid.state.s, 16);
    assert.equal(
        rotatedSn,
        anchoredSn,
        `rotation must supersede the stuck anchor at sn ${anchoredSn}, landed at ${rotatedSn}`
    );
}

/** An exn is signed under the group's establishment event, so the rotation moves past it. */
function assertKeyStateAdvanced(group: MultisigGroup, signedAtSn: number) {
    const rotatedSn = parseInt(group.aid.state.s, 16);
    assert(
        rotatedSn > signedAtSn,
        `rotation must move past the sn the exn was signed under (${signedAtSn}), landed at ${rotatedSn}`
    );
}

/** The half-signed attempt must still be unfinished, or there is nothing to be blocked by. */
async function assertStillPending(client: SignifyClient, op: { name: string }) {
    const current = await client.operations().get(op.name);
    assert.equal(current.done, false, `${op.name} should still be pending`);
}
