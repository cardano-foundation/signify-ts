import { assert, beforeAll, test, expect } from 'vitest';
import { Ilks, Saider, Serder, SignifyClient } from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env.ts';
import {
    createAid,
    getOrCreateClients,
    getOrCreateContact,
    markAndRemoveNotification,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util.ts';
import { retry } from './utils/retry.ts';
import { step } from './utils/test-step.ts';
const { vleiServerUrl } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const LE_SCHEMA_SAID = 'ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY';
const CARDANO_SCHEMA_SAID = 'EFldQpJ2WY2_f2vfNYW_5SK6_IissMcpqzhsG3uO12aq';
const vLEIServerHostUrl = `${vleiServerUrl}/oobi`;
const QVI_SCHEMA_URL = `${vLEIServerHostUrl}/${QVI_SCHEMA_SAID}`;
const LE_SCHEMA_URL = `${vLEIServerHostUrl}/${LE_SCHEMA_SAID}`;
const CARDANO_SCHEMA_URL = `https://cred-issuance.demo.idw-sandboxes.cf-deployments.org/oobi/${CARDANO_SCHEMA_SAID}`;

interface Aid {
    name: string;
    prefix: string;
    oobi: string;
}

function createTimestamp() {
    return new Date().toISOString().replace('Z', '000+00:00');
}

let gleifClient: SignifyClient;
let qviClient: SignifyClient
let legalEntityClient: SignifyClient;;

let gleifAid: Aid;
let qviAid: Aid
let legalEntityAid: Aid;;

beforeAll(async () => {
    [gleifClient, qviClient, legalEntityClient] =
        await getOrCreateClients(3);
});

beforeAll(async () => {
    [gleifAid, qviAid, legalEntityAid] = await Promise.all([
        createAid(gleifClient, 'gleif'),
        createAid(qviClient, 'qvi'),
        createAid(legalEntityClient, 'legal-entity'),
    ]);
});

// Set these!
const cardanoAid = { prefix: '', oobi: '' };

beforeAll(() => {
    assert.notEqual(cardanoAid.prefix, '', 'Please set the cardanoAid parameters to your Java AID and OOBI');
    assert.notEqual(cardanoAid.oobi, '', 'Please set the cardanoAid parameters to your Java AID and OOBI');
})

beforeAll(async () => {
    await Promise.all([
        getOrCreateContact(gleifClient, 'qvi', qviAid.oobi),
        getOrCreateContact(qviClient, 'gleif', gleifAid.oobi),
        getOrCreateContact(qviClient, 'legal-entity', legalEntityAid.oobi),
        getOrCreateContact(legalEntityClient, 'qvi', qviAid.oobi),
        getOrCreateContact(legalEntityClient, 'cardano-java-client', cardanoAid.oobi),
    ]);
});

test('single signature credentials', { timeout: 90000 }, async () => {
    await step('Resolve schema oobis', async () => {
        await Promise.all([
            resolveOobi(gleifClient, QVI_SCHEMA_URL),
            resolveOobi(gleifClient, LE_SCHEMA_URL),
            resolveOobi(qviClient, QVI_SCHEMA_URL),
            resolveOobi(qviClient, LE_SCHEMA_URL),
            resolveOobi(qviClient, CARDANO_SCHEMA_URL),
            resolveOobi(legalEntityClient, QVI_SCHEMA_URL),
            resolveOobi(legalEntityClient, LE_SCHEMA_URL),
            resolveOobi(legalEntityClient, CARDANO_SCHEMA_URL),
        ]);
    });

    const registry = await step('Create registry', async () => {
        const registryName = 'vLEI-test-registry';
        const updatedRegistryName = 'vLEI-test-registry-1';
        const regResult = await gleifClient
            .registries()
            .create({ name: gleifAid.name, registryName: registryName });

        await waitOperation(gleifClient, await regResult.op());
        let registries = await gleifClient.registries().list(gleifAid.name);
        const registry: { name: string; regk: string } = registries[0];
        assert.equal(registries.length, 1);
        assert.equal(registry.name, registryName);

        await gleifClient
            .registries()
            .rename(gleifAid.name, registryName, updatedRegistryName);

        registries = await gleifClient.registries().list(gleifAid.name);
        const updateRegistry: { name: string; regk: string } = registries[0];
        assert.equal(registries.length, 1);
        assert.equal(updateRegistry.name, updatedRegistryName);

        return updateRegistry;
    });

    const qviCredentialId = await step('create QVI credential', async () => {
        const vcdata = {
            LEI: '5493001KJTIIGC8Y1R17',
        };

        const issResult = await gleifClient
            .credentials()
            .issue(gleifAid.name, {
                ri: registry.regk,
                s: QVI_SCHEMA_SAID,
                a: {
                    i: qviAid.prefix,
                    ...vcdata,
                },
            });

        await waitOperation(gleifClient, issResult.op);
        return issResult.acdc.sad.d as string;
    });

    await step('issuer IPEX grant', async () => {
        const dt = createTimestamp();
        const issuerCredential = await gleifClient
            .credentials()
            .get(qviCredentialId);
        assert(issuerCredential !== undefined);

        const [grant, gsigs, gend] = await gleifClient.ipex().grant({
            senderName: gleifAid.name,
            acdc: new Serder(issuerCredential.sad),
            anc: new Serder(issuerCredential.anc),
            iss: new Serder(issuerCredential.iss),
            ancAttachment: issuerCredential.ancatc,
            recipient: qviAid.prefix,
            datetime: dt,
        });

        const op = await gleifClient
            .ipex()
            .submitGrant(gleifAid.name, grant, gsigs, gend, [
                qviAid.prefix,
            ]);
        await waitOperation(gleifClient, op);
    });

    await step(
        'holder can get the credential status before or without holding',
        async () => {
            const state = await retry(async () =>
                qviClient.credentials().state(registry.regk, qviCredentialId)
            );
            assert.equal(state.i, qviCredentialId);
            assert.equal(state.ri, registry.regk);
            assert.equal(state.et, Ilks.iss);
        }
    );

    await step('holder IPEX admit', async () => {
        const holderNotifications = await waitForNotifications(
            qviClient,
            '/exn/ipex/grant'
        );
        const grantNotification = holderNotifications[0]; // should only have one notification right now

        const [admit, sigs, aend] = await qviClient.ipex().admit({
            senderName: qviAid.name,
            message: '',
            grantSaid: grantNotification.a.d!,
            recipient: gleifAid.prefix,
            datetime: createTimestamp(),
        });
        const op = await qviClient
            .ipex()
            .submitAdmit(qviAid.name, admit, sigs, aend, [gleifAid.prefix]);
        await waitOperation(qviClient, op);

        await markAndRemoveNotification(qviClient, grantNotification);
    });

    await step('issuer IPEX grant response', async () => {
        const issuerNotifications = await waitForNotifications(
            gleifClient,
            '/exn/ipex/admit'
        );
        await markAndRemoveNotification(gleifClient, issuerNotifications[0]);
    });

    await step('holder has credential', async () => {
        const holderCredential = await retry(async () => {
            const result = await qviClient
                .credentials()
                .get(qviCredentialId);
            assert(result !== undefined);
            return result;
        });
        assert.equal(holderCredential.sad.s, QVI_SCHEMA_SAID);
        assert.equal(holderCredential.sad.i, gleifAid.prefix);
        assert.equal(holderCredential.status.s, '0');
        assert(holderCredential.atc !== undefined);
    });

    const holderRegistry: { regk: string } = await step(
        'holder create registry for LE credential',
        async () => {
            const registryName = 'vLEI-test-registry';
            const regResult = await qviClient
                .registries()
                .create({ name: qviAid.name, registryName: registryName });

            await waitOperation(qviClient, await regResult.op());
            const registries = await qviClient
                .registries()
                .list(qviAid.name);
            assert(registries.length >= 1);
            return registries[0];
        }
    );

    const leCredentialId = await step(
        'holder create LE (chained) credential',
        async () => {
            const qviCredential = await qviClient
                .credentials()
                .get(qviCredentialId);

            const result = await qviClient
                .credentials()
                .issue(qviAid.name, {
                    a: {
                        i: legalEntityAid.prefix,
                        LEI: '5493001KJTIIGC8Y1R17',
                    },
                    ri: holderRegistry.regk,
                    s: LE_SCHEMA_SAID,
                    r: Saider.saidify({
                        d: '',
                        usageDisclaimer: {
                            l: 'Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.',
                        },
                        issuanceDisclaimer: {
                            l: 'All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.',
                        },
                    })[1],
                    e: Saider.saidify({
                        d: '',
                        qvi: {
                            n: qviCredential.sad.d,
                            s: qviCredential.sad.s,
                        },
                    })[1],
                });

            await waitOperation(qviClient, result.op);
            return result.acdc.sad.d;
        }
    );

    await step('LE credential IPEX grant', async () => {
        const dt = createTimestamp();
        const leCredential = await qviClient
            .credentials()
            .get(leCredentialId);
        assert(leCredential !== undefined);

        const [grant, gsigs, gend] = await qviClient.ipex().grant({
            senderName: qviAid.name,
            acdc: new Serder(leCredential.sad),
            anc: new Serder(leCredential.anc),
            iss: new Serder(leCredential.iss),
            ancAttachment: leCredential.ancatc,
            recipient: legalEntityAid.prefix,
            datetime: dt,
        });

        const op = await qviClient
            .ipex()
            .submitGrant(qviAid.name, grant, gsigs, gend, [
                legalEntityAid.prefix,
            ]);
        await waitOperation(qviClient, op);
    });

    await step('Legal Entity IPEX admit', async () => {
        const notifications = await waitForNotifications(
            legalEntityClient,
            '/exn/ipex/grant'
        );
        const grantNotification = notifications[0];

        const [admit, sigs, aend] = await legalEntityClient.ipex().admit({
            senderName: legalEntityAid.name,
            message: '',
            grantSaid: grantNotification.a.d!,
            recipient: qviAid.prefix,
            datetime: createTimestamp(),
        });

        const op = await legalEntityClient
            .ipex()
            .submitAdmit(legalEntityAid.name, admit, sigs, aend, [
                qviAid.prefix,
            ]);
        await waitOperation(legalEntityClient, op);

        await markAndRemoveNotification(legalEntityClient, grantNotification);
    });

    const legalEntityRegistry: { regk: string } = await step(
        'legal entity create registry for Cardano credential',
        async () => {
            const registryName = 'cardano-registry';
            const regResult = await legalEntityClient
                .registries()
                .create({ name: legalEntityAid.name, registryName: registryName });

            await waitOperation(legalEntityClient, await regResult.op());
            const registries = await legalEntityClient
                .registries()
                .list(legalEntityAid.name);
            assert(registries.length >= 1);
            return registries[0];
        }
    );

    const cardanoCredentialId = await step(
        'legal entity create Cardano (chained) credential',
        async () => {
            const leCredential = await legalEntityClient
                .credentials()
                .get(leCredentialId);

            const result = await legalEntityClient
                .credentials()
                .issue(legalEntityAid.name, {
                    a: {
                        i: cardanoAid.prefix,
                        label: 1337,
                    },
                    ri: legalEntityRegistry.regk,
                    s: CARDANO_SCHEMA_SAID,
                    e: Saider.saidify({
                        d: '',
                        le: {
                            n: leCredential.sad.d,
                            s: leCredential.sad.s,
                        },
                    })[1],
                });

            await waitOperation(legalEntityClient, result.op);
            return result.acdc.sad.d;
        }
    );
    
    await step('Cardano credential IPEX grant', async () => {
        const dt = createTimestamp();
        const cardanoCredential = await legalEntityClient
            .credentials()
            .get(leCredentialId);
        assert(cardanoCredential !== undefined);

        const [grant, gsigs, gend] = await legalEntityClient.ipex().grant({
            senderName: legalEntityAid.name,
            acdc: new Serder(cardanoCredential.sad),
            anc: new Serder(cardanoCredential.anc),
            iss: new Serder(cardanoCredential.iss),
            ancAttachment: cardanoCredential.ancatc,
            recipient: cardanoAid.prefix,
            datetime: dt,
        });

        const op = await legalEntityClient
            .ipex()
            .submitGrant(legalEntityAid.name, grant, gsigs, gend, [
                cardanoAid.prefix,
            ]);
        await waitOperation(legalEntityClient, op);
    });
});
