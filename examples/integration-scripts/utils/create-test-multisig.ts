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
import { waitAndMarkNotification, waitOperation } from './test-util';
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
    op = await client.operations().wait(op, { signal: AbortSignal.timeout(30000) });
    if (!op) throw new Error(`Operation ${op?.name ?? 'unknown'} timed out or returned null`);
    await client.operations().delete(op.name);
    return op;
}

async function createMultisigGroup(
    m1Client: SignifyClient,
    m2Client: SignifyClient,
    groupName: string,
    m1Hab: any,
    m2Hab: any,
    witnessIds: string[]
): Promise<{ prefix: string }> {
    const existing = await m1Client.identifiers().get(groupName).catch(() => null);
    if (existing) {
        console.log(`Group ${groupName} already exists with prefix=${existing.prefix}`);
        return { prefix: existing.prefix };
    }

    console.log(`Waiting for key states for M1=${m1Hab.prefix} and M2=${m2Hab.prefix}`);

    const m1KeyStates = await m1Client.keyStates().get(m1Hab.prefix);
    const m2KeyStates = await m2Client.keyStates().get(m2Hab.prefix);

    console.log(`M1 keyState response:`, JSON.stringify(m1KeyStates));
    console.log(`M2 keyState response:`, JSON.stringify(m2KeyStates));

    const m1State = m1KeyStates[0];
    const m2State = m2KeyStates[0];
    const states = [m1State, m2State];
    const smids = states.map((s: any) => s.i);

    const icpResult1 = await m1Client.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: m1Hab,
        isith: 2,
        nsith: 2,
        toad: witnessIds.length,
        wits: witnessIds,
        states,
        rstates: states,
    });
    const op1 = await icpResult1.op();

    const sigers1 = icpResult1.sigs.map((s: string) => new Siger({ qb64: s }));
    const ims1 = d(messagize(icpResult1.serder, sigers1));
    const atc1 = ims1.substring(icpResult1.serder.size);

    await m1Client.exchanges().send(
        'm1', 'multisig', m1Hab,
        '/multisig/icp',
        { gid: icpResult1.serder.pre, smids, rmids: smids },
        { icp: [icpResult1.serder, atc1] },
        [m2Hab.prefix]
    );
    console.log(`M1 sent /multisig/icp for group ${icpResult1.serder.pre}`);

    const msgSaid = await waitAndMarkNotification(m2Client, '/multisig/icp');
    const req = await m2Client.groups().getRequest(msgSaid);
    const icp = req[0].exn.e.icp;

    const m1State2 = (await m2Client.keyStates().get(m1Hab.prefix))[0];
    const m2State2 = (await m2Client.keyStates().get(m2Hab.prefix))[0];

    const icpResult2 = await m2Client.identifiers().create(groupName, {
        algo: Algos.group,
        mhab: m2Hab,
        isith: icp.kt,
        nsith: icp.nt,
        toad: parseInt(icp.bt),
        wits: icp.b,
        states: [m1State2, m2State2],
        rstates: [m1State2, m2State2],
    });
    const op2 = await icpResult2.op();

    const sigers2 = icpResult2.sigs.map((s: string) => new Siger({ qb64: s }));
    const ims2 = d(messagize(icpResult2.serder, sigers2));
    const atc2 = ims2.substring(icpResult2.serder.size);

    await m2Client.exchanges().send(
        'm2', 'multisig', m2Hab,
        '/multisig/icp',
        { gid: icpResult2.serder.pre, smids, rmids: smids },
        { icp: [icpResult2.serder, atc2] },
        [m1Hab.prefix]
    );
    console.log('M2 sent /multisig/icp back to M1');

    await Promise.all([
        waitOp(m1Client, op1),
        waitOp(m2Client, op2),
    ]);
    console.log(`Group ${icpResult1.serder.pre} created`);

    const g1HabM1 = await m1Client.identifiers().get(groupName);
    const members = await m1Client.identifiers().members(groupName);
    const signings: any[] = members['signing'];
    const stamp = signifyDatetime();

    for (const signing of signings) {
        const eid = Object.keys(signing.ends.agent)[0];
        console.log(`Adding agent end role for eid=${eid}`);

        const m1Res = await m1Client.identifiers().addEndRole(groupName, 'agent', eid, stamp);
        const op1r = await m1Res.op();
        const rpy1 = m1Res.serder;
        const sigs1 = m1Res.sigs;
        const state1 = g1HabM1.state;
        const seal1 = ['SealEvent', { i: g1HabM1.prefix, s: state1.ee.s, d: state1.ee.d }];
        const sigers1 = sigs1.map((s: string) => new Siger({ qb64: s }));
        const ims1 = d(messagize(rpy1, sigers1, seal1, undefined, undefined, false));
        await m1Client.exchanges().send(
            'm1', 'multisig', m1Hab,
            '/multisig/rpy',
            { gid: g1HabM1.prefix },
            { rpy: [rpy1, ims1.substring(rpy1.size)] },
            [m2Hab.prefix]
        );

        const rpyMsgSaid = await waitAndMarkNotification(m2Client, '/multisig/rpy');
        const rpyReq = await m2Client.groups().getRequest(rpyMsgSaid);
        const exn = rpyReq[0].exn;
        const m2Res = await m2Client.identifiers().addEndRole(groupName, exn.e.rpy.a.role, exn.e.rpy.a.eid, exn.e.rpy.dt);
        const op2r = await m2Res.op();
        const rpy2 = m2Res.serder;
        const sigs2 = m2Res.sigs;
        const g1HabM2 = await m2Client.identifiers().get(groupName);
        const state2 = g1HabM2.state;
        const seal2 = ['SealEvent', { i: g1HabM2.prefix, s: state2.ee.s, d: state2.ee.d }];
        const sigers2 = sigs2.map((s: string) => new Siger({ qb64: s }));
        const ims2 = d(messagize(rpy2, sigers2, seal2, undefined, undefined, false));
        await m2Client.exchanges().send(
            'm2', 'multisig', m2Hab,
            '/multisig/rpy',
            { gid: g1HabM2.prefix },
            { rpy: [rpy2, ims2.substring(rpy2.size)] },
            [m1Hab.prefix]
        );

        await Promise.all([
            waitOp(m1Client, op1r),
            waitOp(m2Client, op2r),
        ]);
        console.log(`Agent end role for eid=${eid} added`);
    }

    return { prefix: g1HabM1.prefix };
}

function rewriteOobi(oobi: string): string {
    if (env.preset !== 'local') return oobi;
    return oobi
        .replace(/http:\/\/keria:/g, 'http://127.0.0.1:')
        .replace(/http:\/\/witness-demo:/g, 'http://127.0.0.1:');
}

async function main() {
    console.log('Creating multisig group G1...\n');

    const [m1Client, m2Client] = await Promise.all([
        getClientFromFile('m1'),
        getClientFromFile('m2'),
    ]);

    const m1Hab = await m1Client.identifiers().get('m1');
    const m2Hab = await m2Client.identifiers().get('m2');

    console.log(`M1 prefix: ${m1Hab.prefix}`);
    console.log(`M2 prefix: ${m2Hab.prefix}`);

    // M1 and M2 must know each other before forming the group.
    // Resolve mutual OOBIs so keyStates().get() works and /multisig/icp can be sent.
    console.log('Resolving M1<->M2 OOBIs...');
    const m1Oobi = rewriteOobi((await m1Client.oobis().get('m1', 'agent')).oobis[0]);
    const m2Oobi = rewriteOobi((await m2Client.oobis().get('m2', 'agent')).oobis[0]);
    await Promise.all([
        m1Client.oobis().resolve(m2Oobi, 'm2').then((op: any) => waitOp(m1Client, op)),
        m2Client.oobis().resolve(m1Oobi, 'm1').then((op: any) => waitOp(m2Client, op)),
    ]);
    console.log('M1<->M2 OOBIs resolved');

    const groupData = await createMultisigGroup(
        m1Client, m2Client, 'G1v2', m1Hab, m2Hab, [WAN, WIL, WES]
    );

    const m1Oobis = (await m1Client.oobis().get('G1v2', 'agent')).oobis;
    const m2Oobis = (await m2Client.oobis().get('G1v2', 'agent')).oobis;

    const groupInfo = {
        name: 'G1v2',
        prefix: groupData.prefix,
        m1Bran: (JSON.parse(fs.readFileSync(clientsPath, 'utf-8')) as any).m1.bran,
        m2Bran: (JSON.parse(fs.readFileSync(clientsPath, 'utf-8')) as any).m2.bran,
        oobis: {
            m1: m1Oobis,
            m2: m2Oobis,
        },
    };

    fs.writeFileSync(groupOutputPath, JSON.stringify(groupInfo, null, 2));
    console.log(`\nGroup written to ${groupOutputPath}`);
    console.log(`Group prefix: ${groupData.prefix}`);
}

main().catch(console.error);