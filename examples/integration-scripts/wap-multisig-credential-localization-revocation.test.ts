import { CredentialData, randomNonce, SignifyClient } from 'signify-ts';
import {
    buildCredentialEmbed,
    buildRegistryEmbed,
    computeRegk,
    SCHEMA_SAID,
    signifyDatetime,
} from './utils/wap-operations';
import { setupWapEnvironment } from './utils/wap-setup';
import { sleep, waitOperation } from './utils/test-util';

const GROUP_NAME = 'G2of3CredentialLocalizationRevocation';

async function waitLongOperation(
    client: SignifyClient,
    operation: any
): Promise<any> {
    return waitOperation(client, operation, AbortSignal.timeout(90000));
}

async function localizeRegistry(
    client: SignifyClient,
    registryKey: string,
    registryName: string
): Promise<void> {
    let lastError: unknown;

    for (let attempt = 0; attempt < 30; attempt++) {
        const registries = await client
            .registries()
            .list(GROUP_NAME)
            .catch(() => []);
        if (registries.some((registry: any) => registry.regk === registryKey)) {
            return;
        }

        try {
            await client
                .registries()
                .rename(GROUP_NAME, registryKey, registryName);
            return;
        } catch (error) {
            lastError = error;
            await sleep(1000);
        }
    }

    throw new Error(
        `Unable to localize registry ${registryKey}: ${String(lastError)}`
    );
}

async function pollIncomingExchanges(
    client: SignifyClient,
    route: string,
    correlationId: string,
    excludeSender: string,
    count: number,
    timeoutMs = 90000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const exchanges = await client.exchanges().list({
            filter: { '-r': route },
            limit: 2000,
        });
        const matching = exchanges.filter(
            (exchange: any) =>
                exchange.exn.a?.cid === correlationId &&
                exchange.exn.i !== excludeSender
        );
        if (matching.length >= count) {
            return matching;
        }
        await sleep(1000);
    }

    throw new Error(
        `Timeout waiting for ${count} ${route} exchanges for ${correlationId}`
    );
}

async function issueWithM1AndM2(
    m1: any,
    m2: any,
    m3: any,
    g1M1: any,
    g1M2: any,
    credentialData: CredentialData,
    correlationId: string,
    anchorPoint?: { sn: number; d: string }
): Promise<any> {
    const issuedByM1 = await m1.client
        .credentials()
        .issue(GROUP_NAME, credentialData, anchorPoint);
    await m1.client
        .exchanges()
        .send(
            m1.name,
            'multisig',
            m1.hab,
            '/multisig/iss',
            { gid: g1M1.prefix, cid: correlationId },
            await buildCredentialEmbed(m1.client, g1M1, issuedByM1),
            [m2.aid, m3.aid]
        );

    const [issExchange] = await pollIncomingExchanges(
        m2.client,
        '/multisig/iss',
        correlationId,
        m2.aid,
        1
    );
    const acdc = issExchange.exn.e.acdc as Record<string, unknown>;
    const iss = issExchange.exn.e.iss as { ri: string };
    const issAnchor = issExchange.exn.e.anc as {
        s: string;
        p: string;
    };
    const issuedByM2 = await m2.client.credentials().issue(
        GROUP_NAME,
        {
            i: g1M2.prefix,
            ri: iss.ri,
            s: acdc.s as string,
            a: acdc.a as Record<string, unknown>,
            ...(acdc.u ? { u: acdc.u as string } : {}),
        },
        {
            sn: parseInt(issAnchor.s, 16) - 1,
            d: issAnchor.p,
        }
    );
    await m2.client
        .exchanges()
        .send(
            m2.name,
            'multisig',
            m2.hab,
            '/multisig/iss',
            { gid: g1M2.prefix, cid: correlationId },
            await buildCredentialEmbed(m2.client, g1M2, issuedByM2),
            [m1.aid, m3.aid]
        );

    await Promise.all([
        waitLongOperation(m1.client, issuedByM1.op),
        waitLongOperation(m2.client, issuedByM2.op),
    ]);
    await pollIncomingExchanges(
        m3.client,
        '/multisig/iss',
        correlationId,
        m3.aid,
        2
    );

    return issuedByM1;
}

async function waitForCredential(
    client: SignifyClient,
    credentialSaid: string
): Promise<any> {
    let lastError: unknown;
    for (let attempt = 0; attempt < 30; attempt++) {
        try {
            return await client.credentials().get(credentialSaid);
        } catch (error) {
            lastError = error;
            await sleep(1000);
        }
    }
    throw lastError;
}

describe('2-of-3 multisig credential localization', () => {
    it('reproduces M3 credential 404 when issuing into an already-local registry', async () => {
        const setup = await setupWapEnvironment({
            nMembers: 3,
            threshold: 2,
            groupName: GROUP_NAME,
        });
        const [m1, m2, m3] = setup.resolvedMembers;
        const [g1M1, g1M2] = await Promise.all([
            m1.client.identifiers().get(GROUP_NAME),
            m2.client.identifiers().get(GROUP_NAME),
        ]);

        const nonce = randomNonce();
        const registryKey = computeRegk(g1M1.prefix, nonce);
        const registryName = `wap-registry-${nonce}`;
        const runId = Date.now();
        const registryCorrelationId = `registry-localization-${runId}`;
        const firstCredentialData: CredentialData = {
            i: g1M1.prefix,
            ri: registryKey,
            s: SCHEMA_SAID,
            a: {
                i: setup.holderHab.prefix,
                dt: signifyDatetime(),
                attendeeName: 'First credential before localization',
            },
        };

        let registryByM1: any;

        await Promise.all([
            (async () => {
                registryByM1 = await m1.client.registries().create({
                    name: GROUP_NAME,
                    registryName,
                    nonce,
                });

                await m1.client
                    .exchanges()
                    .send(
                        m1.name,
                        'registry',
                        m1.hab,
                        '/multisig/vcp',
                        { gid: g1M1.prefix, cid: registryCorrelationId },
                        buildRegistryEmbed(registryByM1),
                        [m2.aid, m3.aid]
                    );
                await waitLongOperation(m1.client, await registryByM1.op());
            })(),
            (async () => {
                const [vcpExchange] = await pollIncomingExchanges(
                    m2.client,
                    '/multisig/vcp',
                    registryCorrelationId,
                    m2.aid,
                    1
                );
                expect(vcpExchange).toBeDefined();

                const vcpAnchor = vcpExchange.exn.e.anc as {
                    s: string;
                    p: string;
                };
                const registry = await m2.client.registries().create({
                    name: GROUP_NAME,
                    registryName,
                    nonce,
                    anchorPoint: {
                        sn: parseInt(vcpAnchor.s, 16) - 1,
                        d: vcpAnchor.p,
                    },
                });

                await m2.client
                    .exchanges()
                    .send(
                        m2.name,
                        'registry',
                        m2.hab,
                        '/multisig/vcp',
                        { gid: g1M2.prefix, cid: registryCorrelationId },
                        buildRegistryEmbed(registry),
                        [m1.aid, m3.aid]
                    );
                await waitLongOperation(m2.client, await registry.op());
            })(),
        ]);

        await pollIncomingExchanges(
            m3.client,
            '/multisig/vcp',
            registryCorrelationId,
            m3.aid,
            2
        );

        const registryAnchor = {
            sn: parseInt(registryByM1.serder.ked.s as string, 16),
            d: registryByM1.serder.ked.d as string,
        };
        const firstIssuance = await issueWithM1AndM2(
            m1,
            m2,
            m3,
            g1M1,
            g1M2,
            firstCredentialData,
            `first-issuance-${runId}`,
            registryAnchor
        );
        const firstCredentialSaid = firstIssuance.acdc.ked.d as string;
        const firstCredentialOnM3 = await waitForCredential(
            m3.client,
            firstCredentialSaid
        );
        expect(firstCredentialOnM3.sad.d).toBe(firstCredentialSaid);
        console.log('M3 received the first credential before ACK localization');

        // Mirror outbound WAP ACK handling after the first issuance reaches its
        // threshold. The credential server reuses this stable registry nonce for
        // later credentials issued by the same contact.
        await Promise.all(
            [m1, m2, m3].map((member) =>
                localizeRegistry(member.client, registryKey, registryName)
            )
        );
        console.log('All members localized the registry after the first ACK');

        const secondCredentialData: CredentialData = {
            i: g1M1.prefix,
            ri: registryKey,
            s: SCHEMA_SAID,
            a: {
                i: setup.holderHab.prefix,
                dt: signifyDatetime(),
                attendeeName: 'Second credential in the same registry',
            },
        };
        const secondIssuance = await issueWithM1AndM2(
            m1,
            m2,
            m3,
            g1M1,
            g1M2,
            secondCredentialData,
            `second-issuance-${runId}`
        );
        console.log(
            'M2 co-signed the second issuance and broadcast to M1 and M3'
        );

        const credentialSaid = secondIssuance.acdc.ked.d as string;
        await expect(
            m3.client.credentials().get(credentialSaid)
        ).rejects.toThrow(/404 Not Found/);
        console.log('M3 credential lookup returned 404 immediately');

        await sleep(15000);

        await expect(
            m3.client.credentials().get(credentialSaid)
        ).rejects.toThrow(/404 Not Found/);
        console.log('M3 credential lookup still returned 404 after 15 seconds');
    }, 300000);
});
