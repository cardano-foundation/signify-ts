import {
    Algos,
    d,
    messagize,
    randomPasscode,
    ready,
    Siger,
    SignifyClient,
    Tier,
} from 'signify-ts';
import { resolveEnvironment } from './resolve-env';
import { waitAndMarkNotification } from './test-util';

const WAN = 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha';
const WIL = 'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM';
const WES = 'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX';

const SCHEMA_SAID = 'EJxnJdxkHbRw2wVFNe4IUOPLt8fEtg9Sr3WyTjlgKoIb';

export interface ResolvedMember {
    name: string;
    client: SignifyClient;
    aid: string;
    hab: any;
    oobi: string;
}

export interface SetupOptions {
    nMembers?: number;
    threshold?: number;
    groupName?: string;
}

export async function createClient(env: any): Promise<SignifyClient> {
    await ready();
    const bran = randomPasscode().padEnd(21, '_');
    const client = new SignifyClient(env.url, bran, Tier.low, env.bootUrl);
    try {
        await client.connect();
    } catch {
        const res = await client.boot();
        if (!res.ok) throw new Error('Boot failed');
        await client.connect();
    }
    return client;
}

export async function waitOp(client: SignifyClient, op: any): Promise<any> {
    if (!op) throw new Error('Operation is null/undefined');
    op = await client
        .operations()
        .wait(op, { signal: AbortSignal.timeout(60000) });
    if (!op)
        throw new Error(
            `Operation ${op?.name ?? 'unknown'} timed out or returned null`
        );
    await client.operations().delete(op.name);
    return op;
}

export async function waitOperation(
    client: SignifyClient,
    op: any
): Promise<any> {
    return waitOp(client, op);
}

export async function hasEndRole(
    client: SignifyClient,
    alias: string,
    role: string,
    eid: string
): Promise<boolean> {
    try {
        const response: Response = await client.fetch(
            `/identifiers/${alias}/endroles/${role}`,
            'GET',
            null
        );
        if (!response.ok) return false;
        const list = await response.json();
        return list.some((i: any) => i.role === role && i.eid === eid);
    } catch {
        return false;
    }
}

export function rewriteOobi(oobi: string, env: any): string {
    if (env.preset !== 'local') return oobi;
    return oobi
        .replace(/http:\/\/keria:/g, 'http://127.0.0.1:')
        .replace(/http:\/\/witness-demo:/g, 'http://127.0.0.1:');
}

export function signifyDatetime(): string {
    return new Date().toISOString().replace('Z', '000+00:00');
}

function recipientsOf(members: ResolvedMember[], excludeAid: string): string[] {
    return members.filter((m) => m.aid !== excludeAid).map((m) => m.aid);
}

export async function createMultisigGroup(
    members: ResolvedMember[],
    groupName: string,
    isith: number,
    nsith: number,
    witnessIds: string[]
): Promise<{ prefix: string }> {
    const leader = members[0];
    const cosigners = members.slice(1);

    const existing = await leader.client
        .identifiers()
        .get(groupName)
        .catch(() => null);
    if (existing) {
        console.log(
            `Group ${groupName} already exists with prefix=${existing.prefix}`
        );
        return { prefix: existing.prefix };
    }

    console.log(
        `Building ${
            members.length
        }-of-${nsith} (isith=${isith}) group from members: ${members
            .map((m) => m.name)
            .join(', ')}`
    );

    const states = await Promise.all(
        members.map(
            async (m) => (await leader.client.keyStates().get(m.aid))[0]
        )
    );
    const smids = states.map((s: any) => s.i);

    const leaderIcp = await leader.client.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: leader.hab,
        isith,
        nsith,
        toad: witnessIds.length,
        wits: witnessIds,
        states,
        rstates: states,
    });
    const leaderOp = await leaderIcp.op();

    const leaderSigers = leaderIcp.sigs.map(
        (s: string) => new Siger({ qb64: s })
    );
    const leaderIms = d(messagize(leaderIcp.serder, leaderSigers));
    const leaderAtc = leaderIms.substring(leaderIcp.serder.size);

    await leader.client.exchanges().send(
        leader.name,
        'multisig',
        leader.hab,
        '/multisig/icp',
        { gid: leaderIcp.serder.pre, smids, rmids: smids },
        { icp: [leaderIcp.serder, leaderAtc] },
        cosigners.map((c) => c.aid)
    );

    const cosignerOps: Promise<any>[] = [];
    for (const co of cosigners) {
        const msgSaid = await waitAndMarkNotification(
            co.client,
            '/multisig/icp'
        );
        const req = await co.client.groups().getRequest(msgSaid);
        const icp = req[0].exn.e.icp;

        const cosignerStates = await Promise.all(
            members.map(
                async (m) => (await co.client.keyStates().get(m.aid))[0]
            )
        );

        const coIcp = await co.client.identifiers().create(groupName, {
            algo: Algos.group,
            mhab: co.hab,
            isith: icp.kt,
            nsith: icp.nt,
            toad: parseInt(icp.bt),
            wits: icp.b,
            states: cosignerStates,
            rstates: cosignerStates,
        });
        const coOp = await coIcp.op();

        const coSigers = coIcp.sigs.map((s: string) => new Siger({ qb64: s }));
        const coIms = d(messagize(coIcp.serder, coSigers));
        const coAtc = coIms.substring(coIcp.serder.size);

        await co.client
            .exchanges()
            .send(
                co.name,
                'multisig',
                co.hab,
                '/multisig/icp',
                { gid: coIcp.serder.pre, smids, rmids: smids },
                { icp: [coIcp.serder, coAtc] },
                recipientsOf(members, co.aid)
            );

        cosignerOps.push(waitOp(co.client, coOp));
    }

    await Promise.all([waitOp(leader.client, leaderOp), ...cosignerOps]);
    console.log(`Group ${leaderIcp.serder.pre} created`);

    const leaderGroupHab = await leader.client.identifiers().get(groupName);
    const groupMembers = await leader.client.identifiers().members(groupName);
    const signings: any[] = groupMembers['signing'];
    const stamp = signifyDatetime();

    for (const signing of signings) {
        const eid = Object.keys(signing.ends.agent)[0];

        const leaderRes = await leader.client
            .identifiers()
            .addEndRole(groupName, 'agent', eid, stamp);
        const leaderOpRpy = await leaderRes.op();
        const leaderRpy = leaderRes.serder;
        const leaderSigsRpy = leaderRes.sigs;
        const leaderState = leaderGroupHab.state;
        const leaderSeal = [
            'SealEvent',
            {
                i: leaderGroupHab.prefix,
                s: leaderState.ee.s,
                d: leaderState.ee.d,
            },
        ];
        const leaderSigersRpy = leaderSigsRpy.map(
            (s: string) => new Siger({ qb64: s })
        );
        const leaderImsRpy = d(
            messagize(
                leaderRpy,
                leaderSigersRpy,
                leaderSeal,
                undefined,
                undefined,
                false
            )
        );
        await leader.client.exchanges().send(
            leader.name,
            'multisig',
            leader.hab,
            '/multisig/rpy',
            { gid: leaderGroupHab.prefix },
            { rpy: [leaderRpy, leaderImsRpy.substring(leaderRpy.size)] },
            cosigners.map((c) => c.aid)
        );

        const rpyOps: Promise<any>[] = [];
        for (const co of cosigners) {
            const rpyMsgSaid = await waitAndMarkNotification(
                co.client,
                '/multisig/rpy'
            );
            const rpyReq = await co.client.groups().getRequest(rpyMsgSaid);
            const exn = rpyReq[0].exn;
            const coRes = await co.client
                .identifiers()
                .addEndRole(
                    groupName,
                    exn.e.rpy.a.role,
                    exn.e.rpy.a.eid,
                    exn.e.rpy.dt
                );
            const coOpRpy = await coRes.op();
            const coRpy = coRes.serder;
            const coSigsRpy = coRes.sigs;
            const coGroupHab = await co.client.identifiers().get(groupName);
            const coState = coGroupHab.state;
            const coSeal = [
                'SealEvent',
                { i: coGroupHab.prefix, s: coState.ee.s, d: coState.ee.d },
            ];
            const coSigersRpy = coSigsRpy.map(
                (s: string) => new Siger({ qb64: s })
            );
            const coImsRpy = d(
                messagize(
                    coRpy,
                    coSigersRpy,
                    coSeal,
                    undefined,
                    undefined,
                    false
                )
            );
            await co.client
                .exchanges()
                .send(
                    co.name,
                    'multisig',
                    co.hab,
                    '/multisig/rpy',
                    { gid: coGroupHab.prefix },
                    { rpy: [coRpy, coImsRpy.substring(coRpy.size)] },
                    recipientsOf(members, co.aid)
                );
            rpyOps.push(waitOp(co.client, coOpRpy));
        }

        await Promise.all([waitOp(leader.client, leaderOpRpy), ...rpyOps]);
    }

    return { prefix: leaderGroupHab.prefix };
}

export async function setupWapEnvironment(options: SetupOptions = {}) {
    await ready();

    const env = resolveEnvironment();
    const nMembers = options.nMembers ?? 2;
    const threshold = options.threshold ?? nMembers;
    const groupName = options.groupName ?? 'G1v2';

    const memberNames = Array.from({ length: nMembers }, (_, i) => `m${i + 1}`);
    const names = [...memberNames, 'cs', 'holder'];

    console.log(
        `Setting up WAP environment with ${nMembers} members (Threshold: ${threshold})`
    );

    const clients = await Promise.all(names.map(() => createClient(env)));
    const witArgs = { toad: env.witnessIds.length, wits: env.witnessIds };

    const identifiers: any = {};
    const resolvedMembers: ResolvedMember[] = [];
    let csClient!: SignifyClient, holderClient!: SignifyClient;
    let csHab: any, holderHab: any;

    for (let i = 0; i < clients.length; i++) {
        const client = clients[i];
        const name = names[i];

        let id: string;
        try {
            const ident = await client.identifiers().get(name);
            id = ident.prefix;
        } catch {
            const result = await client.identifiers().create(name, witArgs);
            const op = await waitOp(client, await result.op());
            id = op.response.i;
        }

        const eid = client.agent?.pre!;
        if (!(await hasEndRole(client, name, 'agent', eid))) {
            const result = await client
                .identifiers()
                .addEndRole(name, 'agent', eid);
            await waitOp(client, await result.op());
        }

        const oobi = rewriteOobi(
            (await client.oobis().get(name, 'agent')).oobis[0],
            env
        );
        identifiers[name] = {
            bran: client.bran,
            controller: client.controller.pre,
            agent: eid,
            prefix: id,
            oobi,
        };

        const hab = await client.identifiers().get(name);

        if (name === 'cs') {
            csClient = client;
            csHab = hab;
        } else if (name === 'holder') {
            holderClient = client;
            holderHab = hab;
        } else {
            resolvedMembers.push({ name, client, aid: id, hab, oobi });
        }
    }

    identifiers._meta = { memberNames };

    console.log('Resolving pairwise OOBIs between members...');
    await Promise.all(
        resolvedMembers.flatMap((m) =>
            resolvedMembers
                .filter((o) => o.aid !== m.aid)
                .map((o) =>
                    m.client
                        .oobis()
                        .resolve(o.oobi, o.name)
                        .then((op: any) => waitOp(m.client, op))
                )
        )
    );

    const groupData = await createMultisigGroup(
        resolvedMembers,
        groupName,
        threshold,
        nMembers,
        env.witnessIds
    );

    const csOobi = identifiers['cs'].oobi;
    const holderOobi = identifiers['holder'].oobi;
    const schemaOobi = `${
        process.env.SCHEMA_BASE_URL ??
        (env.preset === 'local'
            ? 'http://127.0.0.1:3001'
            : 'http://cred-issuance:3001')
    }/oobi/${SCHEMA_SAID}`;

    console.log('Resolving member <-> external OOBIs...');

    async function resolveWithLog(
        clientName: string,
        targetName: string,
        client: SignifyClient,
        oobi: string
    ) {
        try {
            const op = await client.oobis().resolve(oobi, targetName);
            await waitOp(client, op);
        } catch (e: any) {
            console.error(
                `[OOBI-ERR] ${clientName} failed to resolve ${targetName}: ${e.message}`
            );
        }
    }

    const resolutions: Promise<unknown>[] = [];

    for (const m of resolvedMembers) {
        resolutions.push(
            resolveWithLog(m.name, 'cs', m.client, csOobi),
            resolveWithLog(m.name, 'holder', m.client, holderOobi),
            resolveWithLog(m.name, 'schema', m.client, schemaOobi),
            resolveWithLog('cs', m.name, csClient, m.oobi)
        );
    }
    resolutions.push(
        resolveWithLog('cs', 'holder', csClient, holderOobi),
        resolveWithLog('cs', 'schema', csClient, schemaOobi),
        resolveWithLog('holder', 'schema', holderClient, schemaOobi)
    );

    await Promise.all(resolutions);

    const keriaBase = resolvedMembers[0].oobi.split('/oobi/')[0];
    const groupOobis = resolvedMembers.map((m) => ({
        memberName: m.name,
        url: `${keriaBase}/oobi/${groupData.prefix}/agent/${
            m.client.agent!.pre
        }`,
    }));

    console.log(
        `Resolving group OOBIs (${groupOobis.length}) on CS and holder`
    );
    const groupResolutions: Promise<void>[] = [];

    for (const g of groupOobis) {
        groupResolutions.push(
            (async () => {
                try {
                    const op = await csClient.oobis().resolve(g.url, groupName);
                    await Promise.race([
                        waitOp(csClient, op),
                        new Promise<void>((_, rej) =>
                            setTimeout(() => rej(new Error('timeout')), 30000)
                        ),
                    ]);
                } catch (e: any) {
                    console.log(
                        `[OOBI-ERR] cs resolving group via ${g.memberName}: ${e.message}`
                    );
                }
            })(),
            (async () => {
                try {
                    const op = await holderClient
                        .oobis()
                        .resolve(g.url, groupName);
                    await Promise.race([
                        waitOp(holderClient, op),
                        new Promise<void>((_, rej) =>
                            setTimeout(() => rej(new Error('timeout')), 30000)
                        ),
                    ]);
                } catch (e: any) {
                    console.log(
                        `[OOBI-ERR] holder resolving group via ${g.memberName}: ${e.message}`
                    );
                }
            })()
        );
    }

    await Promise.all(groupResolutions);

    await Promise.all(
        resolvedMembers.map((m) =>
            (async () => {
                try {
                    const op = await m.client.oobis().resolve(csOobi, 'cs');
                    await waitOp(m.client, op);
                } catch (e: any) {
                    console.error(
                        `[OOBI-ERR] ${m.name} failed to re-resolve cs: ${e.message}`
                    );
                }
            })()
        )
    );

    return {
        identifiers,
        groupData,
        resolvedMembers,
        csClient,
        holderClient,
        csHab,
        holderHab,
    };
}
