import signify, { InceptEventSAD, InteractEventSAD, RotateEventSAD, SealSourceTriple } from 'signify-ts';
import { assert, test } from 'vitest';
import { resolveEnvironment } from './utils/resolve-env.ts';
import { assertOperations, waitOperation } from './utils/test-util.ts';

const { url, bootUrl } = resolveEnvironment();

test('randy', async () => {
    await signify.ready();
    // Boot client
    const bran1 = signify.randomPasscode();
    const client1 = new signify.SignifyClient(
        url,
        bran1,
        signify.Tier.low,
        bootUrl
    );
    await client1.boot();
    await client1.connect();
    await client1.state();

    const icpResult = await client1
        .identifiers()
        .create('aid1', { algo: signify.Algos.randy });
    const icpOp = await waitOperation<InceptEventSAD>(client1, await icpResult.op());
    assert.equal(icpOp['done'], true);
    const aid = icpOp['response'];
    const icp = new signify.Serder(aid!);
    assert.equal(icp.verfers.length, 1);
    assert.equal(icp.digers.length, 1);
    assert.equal(icp.sad['kt'], '1');
    assert.equal(icp.sad['nt'], '1');

    const aids = await client1.identifiers().list();
    assert.equal(aids.aids.length, 1);
    const identifier = aids.aids[0];
    assert.equal(identifier?.name, 'aid1');
    assert.equal(identifier?.prefix, icp.pre);

    const interactResult = await client1.identifiers().interact('aid1', [{
        i: icp.pre,
        d: "",
        s: ""
    }]);
    const interactOp = await waitOperation<InteractEventSAD>(client1, await interactResult.op());
    const ked = interactOp['response'];
    const ixn = new signify.Serder(ked!);
    assert.equal(ixn.sad['s'], '1');
    assert.deepEqual([...(ixn.sad['a'] as SealSourceTriple[])], [{
        i: icp.pre,
        d: "",
        s: ""
    }]);

    const client1Aids = await client1.identifiers().list();
    assert.equal(aids.aids.length, 1);
    const client1Aid = client1Aids.aids[0];

    const events = client1.keyEvents();
    let log = await events.get(client1Aid['prefix']);
    assert.equal(log.length, 2);

    const rotateResult = await client1.identifiers().rotate('aid1');
    const rotateOp = await waitOperation<RotateEventSAD>(client1, await rotateResult.op());
    const rotateKed = rotateOp['response'];
    const rot = new signify.Serder(rotateKed!);
    assert.equal(rot.sad['s'], '2');
    assert.equal(rot.verfers.length, 1);
    assert.equal(rot.digers.length, 1);
    assert.notEqual(rot.verfers[0].qb64, icp.verfers[0].qb64);
    assert.notEqual(rot.digers[0].qb64, icp.digers[0].qb64);
    const dig = new signify.Diger(
        { code: signify.MtrDex.Blake3_256 },
        rot.verfers[0].qb64b
    );
    assert.equal(dig.qb64, icp.digers[0].qb64);
    log = await events.get(client1Aid['prefix']);
    assert.equal(log.length, 3);

    await assertOperations(client1);
}, 30000);
