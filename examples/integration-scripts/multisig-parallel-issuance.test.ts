import { strict as assert } from 'assert';
import signify, {
    AnchorPoint,
    CredentialData,
    CredentialSubject,
    CreateIdentiferArgs,
    randomNonce,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    createTimestamp,
    resolveOobi,
    waitOperation,
    getOrCreateClients,
    getOrCreateAID,
} from './utils/test-util';
import {
    addEndRoleMultisig,
    createAIDMultisig,
    createRegistryMultisig,
    issueCredentialMultisig,
} from './utils/multisig-utils';

const { vleiServerUrl, witnessIds } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const QVI_SCHEMA_URL = `${vleiServerUrl}/oobi/${QVI_SCHEMA_SAID}`;

test('multisig issuance with explicit anchorPoint', async () => {
    const [clientIssuer1, clientIssuer2, clientHolder1, clientHolder2] =
        await getOrCreateClients(4);

    const kargsWitnessed: CreateIdentiferArgs = {
        toad: witnessIds.length,
        wits: witnessIds,
    };

    const [aidIssuer1, aidIssuer2, aidHolder1, aidHolder2] = await Promise.all([
        getOrCreateAID(clientIssuer1, 'issuer1', kargsWitnessed),
        getOrCreateAID(clientIssuer2, 'issuer2', kargsWitnessed),
        getOrCreateAID(clientHolder1, 'holder1', {}),
        getOrCreateAID(clientHolder2, 'holder2', {}),
    ]);

    const [oobiIssuer1, oobiIssuer2] = await Promise.all([
        clientIssuer1.oobis().get('issuer1', 'agent'),
        clientIssuer2.oobis().get('issuer2', 'agent'),
    ]);
    await Promise.all([
        resolveOobi(clientIssuer1, oobiIssuer2.oobis[0], 'issuer2'),
        resolveOobi(clientIssuer2, oobiIssuer1.oobis[0], 'issuer1'),
    ]);

    await Promise.all([
        resolveOobi(clientIssuer1, QVI_SCHEMA_URL),
        resolveOobi(clientIssuer2, QVI_SCHEMA_URL),
    ]);

    const rstates = [aidIssuer1.state, aidIssuer2.state];
    const kargsMultisig: CreateIdentiferArgs = {
        algo: signify.Algos.group,
        isith: ['1/2', '1/2'],
        nsith: ['1/2', '1/2'],
        toad: kargsWitnessed.toad,
        wits: kargsWitnessed.wits,
        states: rstates,
        rstates,
    };

    kargsMultisig.mhab = aidIssuer1;
    const inceptionOp1 = await createAIDMultisig(
        clientIssuer1,
        aidIssuer1,
        [aidIssuer2],
        'issuerGroup',
        kargsMultisig,
        true
    );
    kargsMultisig.mhab = aidIssuer2;
    const inceptionOp2 = await createAIDMultisig(
        clientIssuer2,
        aidIssuer2,
        [aidIssuer1],
        'issuerGroup',
        kargsMultisig
    );

    await Promise.all([
        waitOperation(clientIssuer1, inceptionOp1),
        waitOperation(clientIssuer2, inceptionOp2),
    ]);

    const [aidGroupByIssuer1, aidGroupByIssuer2] = await Promise.all([
        clientIssuer1.identifiers().get('issuerGroup'),
        clientIssuer2.identifiers().get('issuerGroup'),
    ]);
    assert.equal(aidGroupByIssuer1.prefix, aidGroupByIssuer2.prefix);
    const aidGroup = aidGroupByIssuer1;

    const ts = createTimestamp();
    const endRoleOps1 = await addEndRoleMultisig(
        clientIssuer1,
        aidGroup.name,
        aidIssuer1,
        [aidIssuer2],
        aidGroup,
        ts,
        true
    );
    const endRoleOps2 = await addEndRoleMultisig(
        clientIssuer2,
        aidGroup.name,
        aidIssuer2,
        [aidIssuer1],
        aidGroup,
        ts
    );
    await Promise.all([
        ...endRoleOps1.map((op) => waitOperation(clientIssuer1, op)),
        ...endRoleOps2.map((op) => waitOperation(clientIssuer2, op)),
    ]);

    const nonce = randomNonce();
    const { op: registryOp1 } = await createRegistryMultisig(
        clientIssuer1,
        aidIssuer1,
        [aidIssuer2],
        aidGroup,
        'issuerRegistry',
        nonce,
        true
    );
    const { op: registryOp2 } = await createRegistryMultisig(
        clientIssuer2,
        aidIssuer2,
        [aidIssuer1],
        aidGroup,
        'issuerRegistry',
        nonce
    );
    await Promise.all([
        waitOperation(clientIssuer1, registryOp1),
        waitOperation(clientIssuer2, registryOp2),
    ]);

    const [regsByIssuer1, regsByIssuer2] = await Promise.all([
        clientIssuer1.registries().list(aidGroup.name),
        clientIssuer2.registries().list(aidGroup.name),
    ]);
    assert.equal(regsByIssuer1[0].regk, regsByIssuer2[0].regk);
    const registry = regsByIssuer1[0];

    const dt1 = createTimestamp();
    const dt2 = createTimestamp();

    const cred1Data: CredentialData = {
        i: aidGroup.prefix,
        ri: registry.regk,
        s: QVI_SCHEMA_SAID,
        a: {
            i: aidHolder1.prefix,
            dt: dt1,
            LEI: '254900OPPU84GM83MG36',
        } as CredentialSubject,
    };
    const cred2Data: CredentialData = {
        i: aidGroup.prefix,
        ri: registry.regk,
        s: QVI_SCHEMA_SAID,
        a: {
            i: aidHolder2.prefix,
            dt: dt2,
            LEI: '875500ELOZEL05BVXV37',
        } as CredentialSubject,
    };

    const { op: cred1OpIssuer1, anc: ancA } = await issueCredentialMultisig(
        clientIssuer1,
        aidIssuer1,
        [aidIssuer2],
        'issuerGroup',
        cred1Data,
        true
    );

    const anchorForCredB: AnchorPoint = { sn: ancA.sn, d: ancA.d };

    const { op: cred2OpIssuer1 } = await issueCredentialMultisig(
        clientIssuer1,
        aidIssuer1,
        [aidIssuer2],
        'issuerGroup',
        cred2Data,
        true,
        anchorForCredB
    );

    const { op: cred1OpIssuer2 } = await issueCredentialMultisig(
        clientIssuer2,
        aidIssuer2,
        [aidIssuer1],
        'issuerGroup',
        cred1Data,
        false
    );

    const { op: cred2OpIssuer2 } = await issueCredentialMultisig(
        clientIssuer2,
        aidIssuer2,
        [aidIssuer1],
        'issuerGroup',
        cred2Data,
        false,
        anchorForCredB
    );

    await Promise.all([
        waitOperation(clientIssuer1, cred1OpIssuer1),
        waitOperation(clientIssuer1, cred2OpIssuer1),
        waitOperation(clientIssuer2, cred1OpIssuer2),
        waitOperation(clientIssuer2, cred2OpIssuer2),
    ]);

    const cred1List = await clientIssuer1.credentials().list({
        filter: {
            '-i': { $eq: aidGroup.prefix },
            '-s': { $eq: QVI_SCHEMA_SAID },
            '-a-i': { $eq: aidHolder1.prefix },
        },
    });
    const cred2List = await clientIssuer1.credentials().list({
        filter: {
            '-i': { $eq: aidGroup.prefix },
            '-s': { $eq: QVI_SCHEMA_SAID },
            '-a-i': { $eq: aidHolder2.prefix },
        },
    });

    assert(cred1List.length > 0, 'cred1 should be issued');
    assert(cred2List.length > 0, 'cred2 should be issued');
    const cred1 = cred1List[0];
    const cred2 = cred2List[0];

    assert.notEqual(cred1.sad.d, cred2.sad.d, 'two distinct credentials');
    assert.equal(cred1.sad.s, QVI_SCHEMA_SAID);
    assert.equal(cred2.sad.s, QVI_SCHEMA_SAID);
    assert.equal(cred1.sad.i, aidGroup.prefix);
    assert.equal(cred2.sad.i, aidGroup.prefix);
    assert.equal(cred1.sad.a.i, aidHolder1.prefix);
    assert.equal(cred2.sad.a.i, aidHolder2.prefix);
    assert.equal(cred1.status.s, '0', 'cred1 should be active');
    assert.equal(cred2.status.s, '0', 'cred2 should be active');

    console.log('Issued cred1 SAID:', cred1.sad.d);
    console.log('Issued cred2 SAID:', cred2.sad.d);
}, 360000);
