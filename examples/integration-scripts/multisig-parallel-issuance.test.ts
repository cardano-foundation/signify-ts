import { strict as assert } from 'assert';
import signify, {
    CredentialData,
    CredentialSubject,
    CreateIdentiferArgs,
    HabState,
    randomNonce,
} from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    createTimestamp,
    getIssuedCredential,
    getOrCreateAID,
    getOrCreateClients,
    getOrCreateContact,
    resolveOobi,
    waitOperation,
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

test('multisig parallel issuance with explicit sn and dig', async () => {
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
        getOrCreateContact(clientIssuer1, 'issuer2', oobiIssuer2.oobis[0]),
        getOrCreateContact(clientIssuer2, 'issuer1', oobiIssuer1.oobis[0]),
    ]);

    await Promise.all([
        resolveOobi(clientIssuer1, QVI_SCHEMA_URL),
        resolveOobi(clientIssuer2, QVI_SCHEMA_URL),
    ]);

    let aidGroupByIssuer1: HabState, aidGroupByIssuer2: HabState;
    try {
        aidGroupByIssuer1 = await clientIssuer1.identifiers().get('issuerGroup');
        aidGroupByIssuer2 = await clientIssuer2.identifiers().get('issuerGroup');
    } catch {
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

        aidGroupByIssuer1 = await clientIssuer1.identifiers().get('issuerGroup');
        aidGroupByIssuer2 = await clientIssuer2.identifiers().get('issuerGroup');
    }
    assert.equal(aidGroupByIssuer1.prefix, aidGroupByIssuer2.prefix);
    const aidGroup = aidGroupByIssuer1;

    let [oobiGroupByIssuer1, oobiGroupByIssuer2] = await Promise.all([
        clientIssuer1.oobis().get(aidGroup.name, 'agent'),
        clientIssuer2.oobis().get(aidGroup.name, 'agent'),
    ]);
    if (
        oobiGroupByIssuer1.oobis.length === 0 ||
        oobiGroupByIssuer2.oobis.length === 0
    ) {
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

        [oobiGroupByIssuer1, oobiGroupByIssuer2] = await Promise.all([
            clientIssuer1.oobis().get(aidGroup.name, 'agent'),
            clientIssuer2.oobis().get(aidGroup.name, 'agent'),
        ]);
    }
    assert.equal(oobiGroupByIssuer1.oobis[0], oobiGroupByIssuer2.oobis[0]);

    let [regsByIssuer1, regsByIssuer2] = await Promise.all([
        clientIssuer1.registries().list(aidGroup.name),
        clientIssuer2.registries().list(aidGroup.name),
    ]);
    if (regsByIssuer1.length === 0 && regsByIssuer2.length === 0) {
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

        [regsByIssuer1, regsByIssuer2] = await Promise.all([
            clientIssuer1.registries().list(aidGroup.name),
            clientIssuer2.registries().list(aidGroup.name),
        ]);
    }
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

    let cred1 = await getIssuedCredential(
        clientIssuer1,
        aidGroup,
        aidHolder1,
        QVI_SCHEMA_SAID
    );
    let cred2 = await getIssuedCredential(
        clientIssuer1,
        aidGroup,
        aidHolder2,
        QVI_SCHEMA_SAID
    );

    if (!cred1 || !cred2) {
        // Both issuers must sign the same ixn, so they need the same sn/dig.
        const groupForCred1 = await clientIssuer1.identifiers().get('issuerGroup');
        assert(
            parseInt(groupForCred1.state.s, 16) >= 1,
            'Registry ixn not committed in group KEL. ' +
                'If running against stale Docker state, run: ' +
                'docker compose down -v && docker compose up --wait'
        );
        const cred1Sn = parseInt(groupForCred1.state.s, 16) + 1;
        const cred1Dig = groupForCred1.state.d;

        const { op: cred1OpIssuer1 } = await issueCredentialMultisig(
            clientIssuer1,
            aidIssuer1,
            [aidIssuer2],
            'issuerGroup',
            cred1Data,
            true,
            cred1Sn,
            cred1Dig
        );
        const { op: cred1OpIssuer2 } = await issueCredentialMultisig(
            clientIssuer2,
            aidIssuer2,
            [aidIssuer1],
            'issuerGroup',
            cred1Data,
            false,
            cred1Sn,
            cred1Dig
        );

        await Promise.all([
            waitOperation(clientIssuer1, cred1OpIssuer1),
            waitOperation(clientIssuer2, cred1OpIssuer2),
        ]);

        // re-fetch after cred1 commits — sn advanced
        const groupAfterCred1 = await clientIssuer1.identifiers().get('issuerGroup');
        const cred2Sn = parseInt(groupAfterCred1.state.s, 16) + 1;
        const cred2Dig = groupAfterCred1.state.d;

        const { op: cred2OpIssuer1 } = await issueCredentialMultisig(
            clientIssuer1,
            aidIssuer1,
            [aidIssuer2],
            'issuerGroup',
            cred2Data,
            true,
            cred2Sn,
            cred2Dig
        );
        const { op: cred2OpIssuer2 } = await issueCredentialMultisig(
            clientIssuer2,
            aidIssuer2,
            [aidIssuer1],
            'issuerGroup',
            cred2Data,
            false,
            cred2Sn,
            cred2Dig
        );

        await Promise.all([
            waitOperation(clientIssuer1, cred2OpIssuer1),
            waitOperation(clientIssuer2, cred2OpIssuer2),
        ]);

        cred1 = await getIssuedCredential(
            clientIssuer1,
            aidGroup,
            aidHolder1,
            QVI_SCHEMA_SAID
        );
        cred2 = await getIssuedCredential(
            clientIssuer1,
            aidGroup,
            aidHolder2,
            QVI_SCHEMA_SAID
        );
    }

    assert(cred1 !== undefined, 'cred1 should be issued');
    assert(cred2 !== undefined, 'cred2 should be issued');
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
