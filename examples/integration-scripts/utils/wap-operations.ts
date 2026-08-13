import {
    AnchorPoint,
    b,
    CredentialData,
    d,
    Ident,
    Ilks,
    messagize,
    MtrDex,
    Prefixer,
    Serials,
    Siger,
    SignifyClient,
    versify,
} from 'signify-ts';
import {
    serializeACDCAttachment,
    serializeIssExnAttachment,
} from '../../../src/keri/core/utils';
import { waitAndMarkNotification } from './test-util';

export const SCHEMA_SAID = 'EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb';

export function computeRegk(issuerAid: string, nonce: string): string {
    const vVersion = versify(Ident.KERI, undefined, Serials.JSON, 0);
    const vcp: Record<string, unknown> = {
        v: vVersion,
        t: Ilks.vcp,
        d: '',
        i: '',
        ii: issuerAid,
        s: '0',
        c: ['NB'],
        bt: '0',
        b: [],
        n: nonce,
    };
    return new Prefixer({ code: MtrDex.Blake3_256 }, vcp).qb64;
}

export function signifyDatetime(): string {
    return new Date().toISOString().replace('Z', '000+00:00');
}

export function buildRegistryEmbed(regResult: any): Record<string, any> {
    const sigers = regResult.sigs.map(
        (sig: string) => new Siger({ qb64: sig })
    );
    const ims = d(messagize(regResult.serder, sigers));
    const atc = ims.substring(regResult.serder.size);
    const vcpAtc = d(serializeIssExnAttachment(regResult.serder));
    return { vcp: [regResult.regser, vcpAtc], anc: [regResult.serder, atc] };
}

export async function buildCredentialEmbed(
    client: SignifyClient,
    gHab: any,
    issResult: any
): Promise<Record<string, any>> {
    const keeper = client.manager!.get(gHab);
    const sigs = await keeper.sign(b(issResult.anc.raw));
    const sigers = sigs.map((s: string) => new Siger({ qb64: s }));
    const ims = d(messagize(issResult.anc, sigers));
    const atc = ims.substring(issResult.anc.size);
    const acdcAtc = d(serializeACDCAttachment(issResult.iss));
    const issAtc = d(serializeIssExnAttachment(issResult.anc));
    return {
        acdc: [issResult.acdc, acdcAtc],
        iss: [issResult.iss, issAtc],
        anc: [issResult.anc, atc],
    };
}

export async function waitForNotificationsCount(
    client: SignifyClient,
    route: string,
    minCount: number,
    timeoutMs = 60000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const res = await client.notifications().list(0, 1000);
        const notes = (res.notes ?? []).filter(
            (n: any) => n.a.r === route && n.r === false
        );
        if (notes.length >= minCount) return notes;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout: waited for ${minCount} notifications route=${route}`
    );
}

export async function pollAllIncomingExchanges(
    client: SignifyClient,
    corrIds: string[],
    excludeSender: string,
    totalCount: number,
    timeoutMs = 90000
): Promise<any[]> {
    const deadline = Date.now() + timeoutMs;
    let attempt = 0;
    while (Date.now() < deadline) {
        const all: any[] = [];
        for (const route of ['/multisig/vcp', '/multisig/iss']) {
            let raw: any[] = [];
            try {
                raw =
                    (await Promise.race([
                        client
                            .exchanges()
                            .list({ filter: { '-r': route }, limit: 2000 }),
                        new Promise<any[]>((_, rej) =>
                            setTimeout(
                                () => rej(new Error('list timeout')),
                                10000
                            )
                        ),
                    ])) ?? [];
            } catch {}
            const filtered = raw.filter(
                (x: any) =>
                    corrIds.includes(x.exn.a?.cid) && x.exn.i !== excludeSender
            );
            all.push(...filtered);
        }
        if (all.length >= totalCount) return all;
        attempt++;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout: waited for ${totalCount} incoming exchanges (corrIds=[${corrIds.join(
            ','
        )}])`
    );
}

export async function pollIncomingAckWrapper(
    client: SignifyClient,
    route: string,
    corrId: string,
    excludeSender: string,
    timeoutMs = 30000
): Promise<any> {
    const deadline = Date.now() + timeoutMs;
    await new Promise((r) => setTimeout(r, 1000));
    while (Date.now() < deadline) {
        const raw =
            (await client
                .exchanges()
                .list({
                    filter: { '-r': route, '-e-exn-p': corrId },
                    limit: 2000,
                })) ?? [];
        const match = raw.filter((x: any) => x.exn.i !== excludeSender);
        if (match.length > 0) return match;
        await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(
        `Timeout: waited for /multisig/exn (ack) for corrId=${corrId}`
    );
}

export async function getIssuanceStatus(
    client: SignifyClient,
    groupId: string,
    requestSaid: string
): Promise<{
    initiatorResponse: 'accepted' | 'declined' | 'pending';
    members: Record<string, any>;
    thresholdMet: boolean;
}> {
    const groupMembers = await client.identifiers().members(groupId);
    const multisigMembersAids = groupMembers.signing.map((m: any) => m.aid);
    const initiatorAid = multisigMembersAids[0];

    const gHab = await client.identifiers().get(groupId);
    const kt = gHab.state.kt;
    const threshold = Array.isArray(kt)
        ? parseInt(kt[0], 16)
        : parseInt(kt, 16);

    const initiatorExchanges =
        (await client
            .exchanges()
            .list({
                filter: {
                    '-r': '/multisig/exn',
                    '-e-exn-p': requestSaid,
                    '-i': initiatorAid,
                },
            })) ?? [];

    if (initiatorExchanges.length === 0) {
        return {
            initiatorResponse: 'pending',
            members: {},
            thresholdMet: false,
        };
    }

    const initiatorExn = initiatorExchanges[0];
    const initiatorRoute = initiatorExn.exn.e?.exn?.r;

    let response: 'accepted' | 'declined' | 'pending';
    if (initiatorRoute === '/wap/iss/ack') response = 'accepted';
    else if (
        initiatorRoute === '/wap/iss/nack' ||
        initiatorRoute?.endsWith('/reject')
    )
        response = 'declined';
    else throw new Error(`UNKNOWN_INITIATOR_ROUTE: ${initiatorRoute}`);

    const signals = await client.groups().getRequest(initiatorExn.exn.d);
    const members: Record<string, any> = {};

    for (const signal of signals) members[signal.exn.i] = signal;

    return {
        initiatorResponse: response,
        members,
        thresholdMet: signals.length >= threshold,
    };
}

export async function createRegistryMultisig(
    client: SignifyClient,
    aid: any,
    otherMembersAIDs: any[],
    multisigAID: any,
    registryName: string,
    nonce: string,
    isInitiator: boolean = false,
    anchorPoint?: AnchorPoint,
    corrId?: string
) {
    if (!isInitiator) await waitAndMarkNotification(client, '/multisig/vcp');

    const vcpResult = await client.registries().create({
        name: multisigAID.name,
        registryName: registryName,
        nonce: nonce,
        anchorPoint,
    });
    const op = await vcpResult.op();

    const regbeds = buildRegistryEmbed(vcpResult);
    const recp = otherMembersAIDs.map((memberAid) => memberAid.prefix);

    const payload: any = { gid: multisigAID.prefix };
    if (corrId) payload.cid = corrId;

    await client
        .exchanges()
        .send(
            aid.name,
            'registry',
            aid,
            '/multisig/vcp',
            payload,
            regbeds,
            recp
        );

    return {
        op,
        ancSn: parseInt(vcpResult.serder.ked['s'], 16),
        ancDig: vcpResult.serder.ked['d'],
        regk: vcpResult.regser.pre,
    };
}

export async function issueCredentialMultisig(
    client: SignifyClient,
    aid: any,
    otherMembersAIDs: any[],
    multisigAIDName: string,
    kargsIss: CredentialData,
    isInitiator: boolean = false,
    anchorPoint?: AnchorPoint,
    corrId?: string
) {
    if (!isInitiator) await waitAndMarkNotification(client, '/multisig/iss');

    const credResult = await client
        .credentials()
        .issue(multisigAIDName, kargsIss, anchorPoint);

    const multisigAID = await client.identifiers().get(multisigAIDName);
    const embeds = await buildCredentialEmbed(client, multisigAID, credResult);
    const recp = otherMembersAIDs.map((memberAid) => memberAid.prefix);

    const payload: any = { gid: multisigAID.prefix };
    if (corrId) payload.cid = corrId;

    await client
        .exchanges()
        .send(
            aid.name,
            'multisig',
            aid,
            '/multisig/iss',
            payload,
            embeds,
            recp
        );

    return {
        op: credResult.op,
        anc: {
            sn: parseInt(credResult.anc.ked['s'] as string, 16),
            d: credResult.anc.ked['d'] as string,
        },
    };
}
