import { strict as assert } from 'assert';
import { Serder, SignifyClient } from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    Aid,
    assertOperations,
    createAid,
    getOrCreateClients,
    getOrCreateContact,
    getOrIssueCredential,
    getReceivedCredential,
    markAndRemoveNotification,
    resolveOobi,
    waitForNotifications,
    waitOperation,
    warnNotifications,
} from './utils/test-util';
import { retry } from './utils/retry';

const { vleiServerUrl } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const QVI_SCHEMA_URL = `${vleiServerUrl}/oobi/${QVI_SCHEMA_SAID}`;

const qviData = { LEI: '254900OPPU84GM83MG36' };

const CRED_RETRY_DEFAULTS = {
    maxSleep: 10000,
    minSleep: 1000,
    maxRetries: undefined,
    timeout: 30000,
};

function createTimestamp() {
    return new Date().toISOString().replace('Z', '000+00:00');
}

// keripy genusify=True prepends this counter before the CESR stream.
// hard='-_AAA' (KERIACDCGenusVersion, hs=5) + soft='BAA' (version 1.0) = fs=8
const KERI_ACDC_GENUS_VERSION_PREFIX = '-_AAABAA';

async function getOrCreateRegistry(
    client: SignifyClient,
    aid: Aid,
    registryName: string
): Promise<{ name: string; regk: string }> {
    let registries = await client.registries().list(aid.name);
    if (registries.length === 0) {
        const regResult = await client
            .registries()
            .create({ name: aid.name, registryName });
        await waitOperation(client, await regResult.op());
        registries = await client.registries().list(aid.name);
    }
    return registries[0];
}

async function sendGrantWithGenusPrefix(
    senderClient: SignifyClient,
    senderAid: Aid,
    recipientAid: Aid,
    credential: any
): Promise<void> {
    const [grant, gsigs, gend] = await senderClient.ipex().grant({
        senderName: senderAid.name,
        acdc: new Serder(credential.sad),
        anc: new Serder(credential.anc),
        iss: new Serder(credential.iss),
        ancAttachment: credential.ancAttachment,
        recipient: recipientAid.prefix,
        datetime: createTimestamp(),
    });

    // inject genus prefix into atc to simulate keripy messagize(genusify=True)
    const atcWithGenus = KERI_ACDC_GENUS_VERSION_PREFIX + gend;

    const op = await senderClient
        .ipex()
        .submitGrant(senderAid.name, grant, gsigs, atcWithGenus, [
            recipientAid.prefix,
        ]);
    await waitOperation(senderClient, op);
}

async function sendAdmitMessage(
    senderClient: SignifyClient,
    senderAid: Aid,
    recipientAid: Aid
): Promise<void> {
    const notifications = await waitForNotifications(
        senderClient,
        '/exn/ipex/grant'
    );
    assert.equal(notifications.length, 1);
    const grantNotification = notifications[0];

    const [admit, sigs, aend] = await senderClient.ipex().admit({
        senderName: senderAid.name,
        message: '',
        grantSaid: grantNotification.a.d!,
        recipient: recipientAid.prefix,
        datetime: createTimestamp(),
    });

    const op = await senderClient
        .ipex()
        .submitAdmit(senderAid.name, admit, sigs, aend, [recipientAid.prefix]);
    await waitOperation(senderClient, op);

    await markAndRemoveNotification(senderClient, grantNotification);
}

test(
    'ipex-grant-genusify: KERIA must handle KERIACDCGenusVersion prefix in IMS',
    async () => {
        const [issuerClient, holderClient] = await getOrCreateClients(2);

        const [issuerAid, holderAid] = await Promise.all([
            createAid(issuerClient, 'issuer'),
            createAid(holderClient, 'holder'),
        ]);

        await Promise.all([
            getOrCreateContact(issuerClient, 'holder', holderAid.oobi),
            getOrCreateContact(holderClient, 'issuer', issuerAid.oobi),
            resolveOobi(issuerClient, QVI_SCHEMA_URL),
            resolveOobi(holderClient, QVI_SCHEMA_URL),
        ]);

        const issuerRegistry = await getOrCreateRegistry(
            issuerClient,
            issuerAid,
            'issuerRegistry'
        );

        const qviCred = await getOrIssueCredential(
            issuerClient,
            issuerAid,
            holderAid,
            issuerRegistry,
            qviData,
            QVI_SCHEMA_SAID
        );

        let holderCred = await getReceivedCredential(holderClient, qviCred.sad.d);

        if (!holderCred) {
            await sendGrantWithGenusPrefix(
                issuerClient,
                issuerAid,
                holderAid,
                qviCred
            );
            await sendAdmitMessage(holderClient, holderAid, issuerAid);

            holderCred = await retry(async () => {
                const cred = await getReceivedCredential(
                    holderClient,
                    qviCred.sad.d
                );
                assert(
                    cred !== undefined,
                    'Holder did not receive credential — KERIA likely crashed on genus prefix'
                );
                return cred;
            }, CRED_RETRY_DEFAULTS);
        }

        assert.equal(holderCred.sad.d, qviCred.sad.d);
        assert.equal(holderCred.sad.s, QVI_SCHEMA_SAID);
        assert.equal(holderCred.sad.i, issuerAid.prefix);
        assert.equal(holderCred.sad.a.i, holderAid.prefix);
        assert.equal(holderCred.status.s, '0');
        assert(holderCred.atc !== undefined);

        await assertOperations(issuerClient, holderClient);
        await warnNotifications(issuerClient, holderClient);
    },
    120000
);
