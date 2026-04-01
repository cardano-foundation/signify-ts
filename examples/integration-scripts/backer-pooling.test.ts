// This scrip also work if you start keria with no config file with witness urls
import { strict as assert } from 'assert';
import signify from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import { resolveOobi, waitOperation } from './utils/test-util';

const BACKER_AIDS = [
    'BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha',
    'BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM',
    'BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX',
];
const { url, bootUrl, witnessUrls } = resolveEnvironment();

test('test backer pooling', async () => {
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
    const state1 = await client1.state();
    console.log(
        'Client connected. Client AID:',
        state1.controller.state.i,
        'Agent AID: ',
        state1.agent.i
    );

    // Client 1 resolves backers OOBI
    await resolveOobi(client1, witnessUrls[0] + `/oobi/${BACKER_AIDS[0]}`, 'wan');
    console.log('Backer wan OOBI resolved');

    await resolveOobi(client1, witnessUrls[1] + `/oobi/${BACKER_AIDS[1]}`, 'wil');
    console.log('Backer wil OOBI resolved');

    await resolveOobi(client1, witnessUrls[2] + `/oobi/${BACKER_AIDS[2]}`, 'wes');
    console.log('Backer wes OOBI resolved');

    // Client 1 creates AID with 1 witness
    let icpResult1 = await client1.identifiers().create('aid1', {
        toad: 3,
        wits: BACKER_AIDS,
    });
    await waitOperation(client1, await icpResult1.op());
    let aid1 = await client1.identifiers().get('aid1');
    console.log('AID:', aid1.prefix);
    assert.equal(aid1.state.b.length, 3);
    assert.equal(aid1.state.b[0], BACKER_AIDS[0]);
    assert.equal(aid1.state.b[1], BACKER_AIDS[1]);
    assert.equal(aid1.state.b[2], BACKER_AIDS[2]);

    icpResult1 = await client1.identifiers().rotate('aid1');
    await waitOperation(client1, await icpResult1.op());
    aid1 = await client1.identifiers().get('aid1');
    assert.equal(aid1.state.b.length, 3);
    assert.equal(aid1.state.b[0], BACKER_AIDS[0]);
    assert.equal(aid1.state.b[1], BACKER_AIDS[1]);
    assert.equal(aid1.state.b[2], BACKER_AIDS[2]);

}, 60000);
