import signify, {
    Algos,
    Siger,
    d,
    messagize,
    interact as srcInteract,
    b as srcB,
} from 'signify-ts';
import {
    getOrCreateClient,
    getOrCreateIdentifier,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util';
import { resolveEnvironment } from './utils/resolve-env';
import { step } from './utils/test-step';
import assert from 'assert';


test('Pse: latestevent returns in-flight event from partial-signature escrow', async () => {
    await signify.ready();
    const env = resolveEnvironment();

    const [client1, client2] = await step('Boot clients', () =>
        Promise.all([getOrCreateClient(), getOrCreateClient()])
    );

    const PSE_GROUP = 'pse-group';
    const PSE_M1 = 'pse-m1';
    const PSE_M2 = 'pse-m2';

    const [[aid1], [aid2]] = await step('Create member AIDs', () =>
        Promise.all([
            getOrCreateIdentifier(client1, PSE_M1),
            getOrCreateIdentifier(client2, PSE_M2),
        ])
    );

    await step('Exchange OOBIs', async () => {
        const [o1, o2] = await Promise.all([
            client1.oobis().get(PSE_M1, 'agent'),
            client2.oobis().get(PSE_M2, 'agent'),
        ]);
        await Promise.all([
            resolveOobi(client1, o2.oobis[0], PSE_M2),
            resolveOobi(client2, o1.oobis[0], PSE_M1),
        ]);
    });

    await step('Create 2-of-2 group', async () => {
        const [hab1, hab2] = await Promise.all([
            client1.identifiers().get(PSE_M1),
            client2.identifiers().get(PSE_M2),
        ]);
        const states = [hab1.state, hab2.state];

        const icp1 = await client1.identifiers().create(PSE_GROUP, {
            algo: Algos.group,
            mhab: hab1,
            isith: 2,
            nsith: 2,
            toad: env.witnessIds.length,
            wits: env.witnessIds,
            states,
            rstates: states,
        });
        const op1 = await icp1.op();
        const sigers1 = icp1.sigs.map((s) => new Siger({ qb64: s }));
        const ims1 = d(messagize(icp1.serder, sigers1));
        await client1
            .exchanges()
            .send(
                PSE_M1,
                PSE_GROUP,
                hab1,
                '/multisig/icp',
                {
                    gid: icp1.serder.pre,
                    smids: [aid1, aid2],
                    rmids: [aid1, aid2],
                },
                { icp: [icp1.serder, ims1.substring(icp1.serder.size)] },
                [aid2]
            );

        const notes = await waitForNotifications(client2, '/multisig/icp');
        await Promise.all(notes.map((n) => client2.notifications().mark(n.i)));
        const req = await client2
            .groups()
            .getRequest(notes[notes.length - 1].a.d!);
        const exn = req[0].exn;
        const icp2 = await client2.identifiers().create(PSE_GROUP, {
            algo: Algos.group,
            mhab: hab2,
            isith: exn.e.icp.kt,
            nsith: exn.e.icp.nt,
            toad: parseInt(exn.e.icp.bt),
            wits: exn.e.icp.b,
            states,
            rstates: states,
        });
        const op2 = await icp2.op();
        const sigers2 = icp2.sigs.map((s) => new Siger({ qb64: s }));
        const ims2 = d(messagize(icp2.serder, sigers2));
        await client2
            .exchanges()
            .send(
                PSE_M2,
                PSE_GROUP,
                hab2,
                '/multisig/icp',
                {
                    gid: icp2.serder.pre,
                    smids: [aid1, aid2],
                    rmids: [aid1, aid2],
                },
                { icp: [icp2.serder, ims2.substring(icp2.serder.size)] },
                [aid1]
            );
        await Promise.all([
            waitOperation(client1, op1),
            waitOperation(client2, op2),
        ]);
    });

    const grpHab = await client1.identifiers().get(PSE_GROUP);
    const groupPrefix = grpHab.prefix;

    await step('Baseline: latestevent sn=0 after inception', async () => {
        const evt = await client1.identifiers().getLatestEvent(PSE_GROUP);
        assert.strictEqual(parseInt(evt.s, 16), 0);
    });

    // Member1 submits ixn sn=1 without member2 co-signing
    await step('Member1 submits ixn sn=1 (no co-sign yet)', async () => {
        const grp = await client1.identifiers().get(PSE_GROUP);
        const hab1 = await client1.identifiers().get(PSE_M1);
        const keeper = client1.manager!.get(grp);
        const serder: any = srcInteract({
            pre: groupPrefix,
            sn: 1,
            dig: grp.state.d,
            data: [],
            version: undefined,
            kind: undefined,
        });
        const sigs: string[] = await keeper.sign(srcB(serder.raw));
        const sigers = sigs.map((s: string) => new Siger({ qb64: s }));
        const jsondata: any = { ixn: serder.ked, sigs, group: true };
        jsondata[keeper.algo] = keeper.params();
        await client1.fetch(
            `/identifiers/${PSE_GROUP}/events`,
            'POST',
            jsondata
        );

        const ims = d(messagize(serder, sigers as any));
        await client1
            .exchanges()
            .send(
                PSE_M1,
                PSE_GROUP,
                hab1,
                '/multisig/ixn',
                { gid: groupPrefix, smids: [aid1, aid2], rmids: [aid1, aid2] },
                { ixn: [serder, ims.substring(serder.size)] },
                [aid2]
            );
    });

    await step(
        'Pse: latestevent reflects sn=1 from partial-sig escrow',
        async () => {
            const evt = await client1.identifiers().getLatestEvent(PSE_GROUP);
            assert.strictEqual(
                parseInt(evt.s, 16),
                1,
                'expected sn=1 from Pse'
            );
            assert.strictEqual(evt.t, 'ixn');
        }
    );
}, 180000);

test('Ooe: latestevent returns highest sn across out-of-order escrow', async () => {
    await signify.ready();
    const env = resolveEnvironment();

    const OOE_AID = 'ooe-singlesig';

    const client = await step('Boot client', () => getOrCreateClient());

    const [hab] = await step('Create AID', () =>
        getOrCreateIdentifier(client, OOE_AID, {
            toad: env.witnessIds.length,
            wits: env.witnessIds,
        })
    );

    const prefix = hab;
    const habState = await client.identifiers().get(OOE_AID);
    const keeper = client.manager!.get(habState);

    // Build sn=1 locally to obtain its SAID, but do not submit it.
    const icpState = habState.state;
    const sn1Serder: any = srcInteract({
        pre: prefix,
        sn: 1,
        dig: icpState.d,
        data: [],
        version: undefined,
        kind: undefined,
    });
    const sn1Said: string = sn1Serder.ked['d'];

    // Submit sn=2, which references the unsubmitted sn=1 → lands in OOO escrow.
    await step('Submit sn=2 (skipping sn=1) → OOO escrow', async () => {
        const serder: any = srcInteract({
            pre: prefix,
            sn: 2,
            dig: sn1Said,
            data: [],
            version: undefined,
            kind: undefined,
        });
        const sigs: string[] = await keeper.sign(srcB(serder.raw));
        const jsondata: any = { ixn: serder.ked, sigs };
        jsondata[keeper.algo] = keeper.params();
        await client.fetch(`/identifiers/${OOE_AID}/events`, 'POST', jsondata);
    });

    await step('Ooe: latestevent returns sn=2 from OOO escrow', async () => {
        const evt = await client.identifiers().getLatestEvent(OOE_AID);
        assert.strictEqual(parseInt(evt.s, 16), 2, 'expected sn=2 from OOO escrow');
    });

    // Now submit sn=1 to fill the gap and drain both events from escrow.
    const op = await step('Submit sn=1 to fill gap', async () => {
        const sigs: string[] = await keeper.sign(srcB(sn1Serder.raw));
        const jsondata: any = { ixn: sn1Serder.ked, sigs };
        jsondata[keeper.algo] = keeper.params();
        const res = await client.fetch(
            `/identifiers/${OOE_AID}/events`,
            'POST',
            jsondata
        );
        return res.json();
    });

    await step('After completion: latestevent sn=2 and kever confirmed', async () => {
        await waitOperation(client, op.name);
        const evt = await client.identifiers().getLatestEvent(OOE_AID);
        assert.strictEqual(parseInt(evt.s, 16), 2);
        const finalHab = await client.identifiers().get(OOE_AID);
        assert.strictEqual(parseInt(finalHab.state.s, 16), 2);
    });
}, 180000);

test('delegables: latestevent returns pending dip/drt from delegation escrow', async () => {
    await signify.ready();
    const env = resolveEnvironment();

    const DELEGATOR = 'del-latestevent-delegator';
    const DELEGATEE = 'del-latestevent-delegatee';

    const [delegatorClient, delegateeClient] = await step('Boot clients', () =>
        Promise.all([getOrCreateClient(), getOrCreateClient()])
    );

    await step('Create delegator AID', async () => {
        await getOrCreateIdentifier(delegatorClient, DELEGATOR, {
            toad: env.witnessIds.length,
            wits: env.witnessIds,
        });
        const rpyRes = await delegatorClient
            .identifiers()
            .addEndRole(DELEGATOR, 'agent', delegatorClient!.agent!.pre);
        await waitOperation(delegatorClient, await rpyRes.op());
    });

    const ator = await delegatorClient.identifiers().get(DELEGATOR);
    const delegatorPrefix = ator.prefix;

    await step('Delegatee resolves delegator OOBI', async () => {
        const oobi = await delegatorClient.oobis().get(DELEGATOR, 'agent');
        await resolveOobi(delegateeClient, oobi.oobis[0], DELEGATOR);
    });

    let delegateePrefix: string;
    const dipOp = await step('Delegatee creates dip', async () => {
        const result = await delegateeClient
            .identifiers()
            .create(DELEGATEE, { delpre: delegatorPrefix });
        const op = await result.op();
        delegateePrefix = op.name.split('.')[1];
        return op;
    });

    await step(
        'delegables: latestevent=dip before delegator anchor',
        async () => {
            const evt = await delegateeClient.identifiers().getLatestEvent(DELEGATEE);
            assert.strictEqual(
                evt.t,
                'dip',
                'expected dip in delegables escrow'
            );
            assert.strictEqual(parseInt(evt.s as string, 16), 0);
        }
    );

    await step('Delegator approves dip', async () => {
        const seal = { i: delegateePrefix, s: '0', d: delegateePrefix };
        const ixnResult = await delegatorClient
            .identifiers()
            .interact(DELEGATOR, seal);
        const ixnOp = await ixnResult.op();
        const ksOp = await delegateeClient
            .keyStates()
            .query(delegatorPrefix, undefined, seal);
        await Promise.all([
            waitOperation(delegatorClient, ixnOp),
            waitOperation(delegateeClient, dipOp),
            waitOperation(delegateeClient, ksOp),
        ]);
    });

    await step(
        'delegables: latestevent=dip after approval (kever.sn=0)',
        async () => {
            const delegatee = await delegateeClient
                .identifiers()
                .get(DELEGATEE);
            assert.strictEqual(parseInt(delegatee.state.s, 16), 0);
            const evt = await delegateeClient.identifiers().getLatestEvent(DELEGATEE);
            assert.strictEqual(evt.t, 'dip');
            assert.strictEqual(parseInt(evt.s as string, 16), 0);
        }
    );

    const drtOp = await step('Delegatee submits drt (sn=1)', async () => {
        const rotResult = await delegateeClient.identifiers().rotate(DELEGATEE);
        return rotResult.op();
    });

    await step(
        'delegables: latestevent=drt while drt awaits anchor',
        async () => {
            const evt = await delegateeClient.identifiers().getLatestEvent(DELEGATEE);
            assert.strictEqual(
                evt.t,
                'drt',
                'expected drt in delegables escrow'
            );
            assert.strictEqual(parseInt(evt.s as string, 16), 1);
        }
    );

    await step('Delegator approves drt', async () => {
        const delegateeState = await delegateeClient
            .identifiers()
            .get(DELEGATEE);
        const seal = {
            i: delegateePrefix,
            s: '1',
            d: delegateeState.state.d,
        };
        const ixnResult = await delegatorClient
            .identifiers()
            .interact(DELEGATOR, seal);
        const ixnOp = await ixnResult.op();
        const ksOp = await delegateeClient
            .keyStates()
            .query(delegatorPrefix, undefined, seal);
        await Promise.all([
            waitOperation(delegatorClient, ixnOp),
            waitOperation(delegateeClient, drtOp),
            waitOperation(delegateeClient, ksOp),
        ]);
    });

    await step(
        'delegables: latestevent=drt after confirmation (kever.sn=1)',
        async () => {
            const delegateeFinal = await delegateeClient
                .identifiers()
                .get(DELEGATEE);
            assert.strictEqual(parseInt(delegateeFinal.state.s, 16), 1);
            const evt = await delegateeClient.identifiers().getLatestEvent(DELEGATEE);
            assert.strictEqual(evt.t, 'drt');
            assert.strictEqual(parseInt(evt.s as string, 16), 1);
        }
    );
}, 180000);
