import { assert, beforeAll, test } from 'vitest';
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
const CARDANO_SCHEMA_SAID = 'EKU2UWx115nPv1JqWVMCFRn0_EMaME08HrUK5cLuTP89';
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
        await getOrCreateClients(3, ['0ADF2TpptgqcDE5IQUF1y', '0ADF2TpptgqcDE5IQUF1z', '0ADF2TpptgqcDE5IQUF1t']);
});

beforeAll(async () => {
    [gleifAid, qviAid, legalEntityAid] = await Promise.all([
        createAid(gleifClient, 'gleif'),
        createAid(qviClient, 'qvi'),
        createAid(legalEntityClient, 'legal-entity'),
    ]);
});

// Set these!
const cardanoAid = { prefix: 'EFQuo2DNv8R3qUdl-_GxRbmFIkeKwgZoyXJnG15_y1Os', oobi: 'http://keria:3902/oobi/EFQuo2DNv8R3qUdl-_GxRbmFIkeKwgZoyXJnG15_y1Os/agent/EMVyas8pPngNUf_YwveBQrh6P0scNom2qTrCS-cIgEFR' };

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

async function getOrCreateRegistry(
    client: SignifyClient,
    aidName: string,
    registryName: string
): Promise<{ name: string; regk: string }> {
    // Check if registry already exists
    let registries = await client.registries().list(aidName);
    let registry = registries.find((r: { name: string }) => r.name === registryName);
    
    if (registry) {
        return registry as { name: string; regk: string };
    }
    
    // Create new registry
    const regResult = await client
        .registries()
        .create({ name: aidName, registryName });

    await waitOperation(client, await regResult.op());
    
    // Get the newly created registry
    registries = await client.registries().list(aidName);
    registry = registries.find((r: { name: string }) => r.name === registryName);
    
    if (!registry) {
        throw new Error(`Failed to create registry "${registryName}"`);
    }
    
    return registry as { name: string; regk: string };
}

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
        const registryName = 'vLEI-test-registry-1';
        
        // Get or create registry
        const registry = await getOrCreateRegistry(gleifClient, gleifAid.name, registryName);
        
        assert.equal(registry.name, registryName);
        return registry;
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
            const registry = await getOrCreateRegistry(qviClient, qviAid.name, registryName);
            return registry;
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
            const registry = await getOrCreateRegistry(legalEntityClient, legalEntityAid.name, registryName);
            return registry;
        }
    );

    const cardanoCredentialId = await step(
        'legal entity create Cardano (chained) credential',
        async () => {
            let leCredential;
            try {
                leCredential = await retry(async () => {
                    return await legalEntityClient.credentials().get(leCredentialId);
                });
            } catch (error) {
                const credentials = await legalEntityClient.credentials().list();
                leCredential = credentials.find((c: any) => c.sad.s === LE_SCHEMA_SAID);
                
                if (!leCredential) {
                    throw new Error(`LE credential not found. Expected SAID: ${leCredentialId}`);
                }
            }

            const result = await legalEntityClient
                .credentials()
                .issue(legalEntityAid.name, {
                    a: {
                        i: cardanoAid.prefix,
                        label: '1337',
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
            .get(cardanoCredentialId);
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
