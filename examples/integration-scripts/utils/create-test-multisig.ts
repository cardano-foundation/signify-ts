import {
    Algos,
    d,
    messagize,
    Siger,
    SignifyClient,
    Tier,
    ready,
} from 'signify-ts';
import { resolveEnvironment } from './resolve-env';
import { waitAndMarkNotification } from './test-util';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const WAN = 'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha';
const WIL = 'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM';
const WES = 'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX';

const env = resolveEnvironment();
const clientsPath = path.join(__dirname, '../../.test-clients.json');
const groupOutputPath = path.join(__dirname, '../../.test-group.json');

// The group is built from m1..mN listed in .test-clients.json._meta.memberNames
// (defaults to ["m1","m2"] for back-compat). THRESHOLD is the signing threshold
// kt; defaults to N (full N-of-N).
const GROUP_NAME = process.env.GROUP_NAME ?? 'G1v2';
const THRESHOLD = process.env.THRESHOLD ? parseInt(process.env.THRESHOLD, 10) : undefined;

function signifyDatetime(): string {
    return new Date().toISOString().replace('Z', '000+00:00');
}

async function getClientFromFile(name: string): Promise<SignifyClient> {
    const clientsData = JSON.parse(fs.readFileSync(clientsPath, 'utf-8'));
    const data = clientsData[name];
    if (!data) throw new Error(`Client ${name} not found in .test-clients.json`);

    await ready();
    const client = new SignifyClient(env.url, data.bran, Tier.low, env.bootUrl);
    await client.connect();
    return client;
}

async function waitOp(client: SignifyClient, op: any): Promise<any> {
    if (!op) throw new Error('Operation is null/undefined');
    op = await client.operations().wait(op, { signal: AbortSignal.timeout(60000) });
    if (!op) throw new Error(`Operation ${op?.name ?? 'unknown'} timed out or returned null`);
    await client.operations().delete(op.name);
    return op;
}

function recipientsOf(members: ResolvedMember[], excludeAid: string): string[] {
    return members.filter(m => m.aid !== excludeAid).map(m => m.aid);
}

interface ResolvedMember {
    name: string;            // m1, m2, ..., mN
    client: SignifyClient;
    aid: string;             // member AID prefix
    hab: any;                // signify hab
}

async function createMultisigGroup(
    members: ResolvedMember[],
    groupName: string,
    isith: number,
    nsith: number,
    witnessIds: string[]
): Promise<{ prefix: string }> {
    const leader = members[0];
    const cosigners = members.slice(1);

    const existing = await leader.client.identifiers().get(groupName).catch(() => null);
    if (existing) {
        console.log(`Group ${groupName} already exists with prefix=${existing.prefix}`);
        return { prefix: existing.prefix };
    }

    console.log(`Building ${members.length}-of-${nsith} (isith=${isith}) group from members: ${members.map(m => m.name).join(', ')}`);

    // Each member needs the others' key states resolved before inception.
    // Fetch the key state for every member from the leader's perspective.
    const states = await Promise.all(
        members.map(async (m) => (await leader.client.keyStates().get(m.aid))[0])
    );
    const smids = states.map((s: any) => s.i);

    // Leader (m1) creates the inception event with the agreed thresholds and
    // broadcasts /multisig/icp to every cosigner.
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

    const leaderSigers = leaderIcp.sigs.map((s: string) => new Siger({ qb64: s }));
    const leaderIms = d(messagize(leaderIcp.serder, leaderSigers));
    const leaderAtc = leaderIms.substring(leaderIcp.serder.size);

    await leader.client.exchanges().send(
        leader.name,
        'multisig',
        leader.hab,
        '/multisig/icp',
        { gid: leaderIcp.serder.pre, smids, rmids: smids },
        { icp: [leaderIcp.serder, leaderAtc] },
        cosigners.map(c => c.aid)
    );
    console.log(`${leader.name} sent /multisig/icp to ${cosigners.length} cosigner(s)`);

    // Each cosigner consumes the notification, mirrors the inception locally
    // using the same kt/nt/wits, and broadcasts its /multisig/icp back to all
    // other members so KERIA can accumulate signatures.
    const cosignerOps: Promise<any>[] = [];
    for (const co of cosigners) {
        const msgSaid = await waitAndMarkNotification(co.client, '/multisig/icp');
        const req = await co.client.groups().getRequest(msgSaid);
        const icp = req[0].exn.e.icp;

        // Refetch states from this cosigner's KERIA. By the time we reach this
        // point all OOBIs are resolved so every key state is available.
        const cosignerStates = await Promise.all(
            members.map(async (m) => (await co.client.keyStates().get(m.aid))[0])
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

        await co.client.exchanges().send(
            co.name,
            'multisig',
            co.hab,
            '/multisig/icp',
            { gid: coIcp.serder.pre, smids, rmids: smids },
            { icp: [coIcp.serder, coAtc] },
            recipientsOf(members, co.aid)
        );
        console.log(`${co.name} sent /multisig/icp to ${members.length - 1} peer(s)`);

        cosignerOps.push(waitOp(co.client, coOp));
    }

    await Promise.all([waitOp(leader.client, leaderOp), ...cosignerOps]);
    console.log(`Group ${leaderIcp.serder.pre} created`);

    // Add agent endRole for every member's agent EID. Each member adds the role
    // locally and broadcasts /multisig/rpy to all other members.
    const leaderGroupHab = await leader.client.identifiers().get(groupName);
    const groupMembers = await leader.client.identifiers().members(groupName);
    const signings: any[] = groupMembers['signing'];
    const stamp = signifyDatetime();

    for (const signing of signings) {
        const eid = Object.keys(signing.ends.agent)[0];
        console.log(`Adding agent end role for eid=${eid}`);

        // Leader adds the role and sends rpy to all cosigners.
        const leaderRes = await leader.client.identifiers().addEndRole(groupName, 'agent', eid, stamp);
        const leaderOpRpy = await leaderRes.op();
        const leaderRpy = leaderRes.serder;
        const leaderSigsRpy = leaderRes.sigs;
        const leaderState = leaderGroupHab.state;
        const leaderSeal = ['SealEvent', { i: leaderGroupHab.prefix, s: leaderState.ee.s, d: leaderState.ee.d }];
        const leaderSigersRpy = leaderSigsRpy.map((s: string) => new Siger({ qb64: s }));
        const leaderImsRpy = d(messagize(leaderRpy, leaderSigersRpy, leaderSeal, undefined, undefined, false));
        await leader.client.exchanges().send(
            leader.name,
            'multisig',
            leader.hab,
            '/multisig/rpy',
            { gid: leaderGroupHab.prefix },
            { rpy: [leaderRpy, leaderImsRpy.substring(leaderRpy.size)] },
            cosigners.map(c => c.aid)
        );

        // Each cosigner consumes the rpy notification and adds the role.
        const rpyOps: Promise<any>[] = [];
        for (const co of cosigners) {
            const rpyMsgSaid = await waitAndMarkNotification(co.client, '/multisig/rpy');
            const rpyReq = await co.client.groups().getRequest(rpyMsgSaid);
            const exn = rpyReq[0].exn;
            const coRes = await co.client.identifiers().addEndRole(
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
            const coSeal = ['SealEvent', { i: coGroupHab.prefix, s: coState.ee.s, d: coState.ee.d }];
            const coSigersRpy = coSigsRpy.map((s: string) => new Siger({ qb64: s }));
            const coImsRpy = d(messagize(coRpy, coSigersRpy, coSeal, undefined, undefined, false));
            await co.client.exchanges().send(
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
        console.log(`Agent end role for eid=${eid} added`);
    }

    return { prefix: leaderGroupHab.prefix };
}

function rewriteOobi(oobi: string): string {
    if (env.preset !== 'local') return oobi;
    return oobi
        .replace(/http:\/\/keria:/g, 'http://127.0.0.1:')
        .replace(/http:\/\/witness-demo:/g, 'http://127.0.0.1:');
}

async function main() {
    const clientsData = JSON.parse(fs.readFileSync(clientsPath, 'utf-8')) as any;
    const memberNames: string[] = clientsData._meta?.memberNames ?? ['m1', 'm2'];
    if (memberNames.length < 2) {
        throw new Error(`Need at least 2 members to form a multisig; got ${memberNames.length}`);
    }

    const isith = THRESHOLD ?? memberNames.length;
    const nsith = THRESHOLD ?? memberNames.length;
    if (isith < 1 || isith > memberNames.length) {
        throw new Error(`THRESHOLD ${isith} out of range for ${memberNames.length}-member group`);
    }
    console.log(`Creating ${isith}-of-${memberNames.length} multisig group ${GROUP_NAME}\n`);

    const members: ResolvedMember[] = await Promise.all(
        memberNames.map(async (name) => {
            const client = await getClientFromFile(name);
            const hab = await client.identifiers().get(name);
            return { name, client, aid: hab.prefix, hab };
        })
    );

    console.log('Members:');
    for (const m of members) {
        console.log(`  ${m.name}: ${m.aid}`);
    }
    console.log('');

    // Each member must know every other member before inception so that
    // keyStates().get(peerAid) succeeds. Resolve every pair lazily.
    const memberOobis = await Promise.all(
        members.map(async (m) => ({
            name: m.name,
            aid: m.aid,
            oobi: rewriteOobi((await m.client.oobis().get(m.name, 'agent')).oobis[0]),
        }))
    );

    console.log('Resolving pairwise OOBIs between members...');
    await Promise.all(
        members.flatMap((m) =>
            memberOobis
                .filter((o) => o.aid !== m.aid)
                .map((o) =>
                    m.client.oobis()
                        .resolve(o.oobi, o.name)
                        .then((op: any) => waitOp(m.client, op))
                )
        )
    );
    console.log('Pairwise OOBIs resolved');

    const groupData = await createMultisigGroup(
        members,
        GROUP_NAME,
        isith,
        nsith,
        [WAN, WIL, WES]
    );

    const m1AgentEid = members[0].client.agent!.pre;
    const keriaBase = memberOobis[0].oobi.split('/oobi/')[0];
    const g1OobiViaM1 = `${keriaBase}/oobi/${groupData.prefix}/agent/${m1AgentEid}`;

    const groupInfo = {
        name: GROUP_NAME,
        prefix: groupData.prefix,
        threshold: isith,
        members: members.map((m) => ({
            name: m.name,
            bran: clientsData[m.name].bran,
            prefix: m.aid,
            agentEid: m.client.agent!.pre,
        })),
        oobi: g1OobiViaM1,
    };

    fs.writeFileSync(groupOutputPath, JSON.stringify(groupInfo, null, 2));
    console.log(`\nGroup written to ${groupOutputPath}`);
    console.log(`Group prefix: ${groupData.prefix}`);
    console.log(`Threshold: ${isith}-of-${memberNames.length}`);
}

main().catch(console.error);
