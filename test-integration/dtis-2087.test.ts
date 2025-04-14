import { assert, test } from 'vitest';
import signify from 'signify-ts';
import { b, Serials } from '../src/keri/core/core.ts';
import { reply } from '../src/keri/core/eventing.ts';
import { resolveEnvironment } from './utils/resolve-env.ts';
import { getOrCreateIdentifier } from './utils/test-util.ts';
import { Salter } from '../src/keri/core/salter.ts';
import libsodium from 'libsodium-wrappers-sumo';
import { p } from '@noble/curves/pasta';
import { Prefixer } from '../src/keri/core/prefixer.ts';
import { MtrDex } from '../src/keri/core/matter.ts';

const { url, bootUrl } = resolveEnvironment();

test('Alice introduces herself to Bob using an ephemeral key pair', async () => {
    await signify.ready();

    // Boot Alice's client
    const aliceBran = "0123456789abcdefghijk"
    const alice = new signify.SignifyClient(url, aliceBran, signify.Tier.low, bootUrl);
    await alice.boot();
    await alice.connect();

    // key pair
    const salter = new Salter({ raw: b(aliceBran) });
    // const signer = salter.signer();
    const signer = salter.signer(
        MtrDex.Ed25519_Seed,
        false,
        '',
        null,
        false
    );
    const keypair = libsodium.crypto_sign_seed_keypair(signer.raw);
    const ephemeralAliceId = new Prefixer({ code: MtrDex.Ed25519N, raw: keypair.publicKey });

    const alice_info = await getOrCreateIdentifier(alice, 'alice');

    // Boot Bob's client
    const bobBran = signify.randomPasscode();
    const bob = new signify.SignifyClient(url, bobBran, signify.Tier.low, bootUrl);
    await bob.boot();
    await bob.connect();

    await getOrCreateIdentifier(alice, 'bob');
    const bobAid = await alice.identifiers().get('bob');

    // Create introduce msg rpy
    const rpyData = {
        'cid': ephemeralAliceId.qb64,
        'oobi': alice_info[1]
    }

    const rpy = reply('/introduce', rpyData, undefined, undefined, Serials.JSON)
    const sig = await signer.sign(b(rpy.raw), 64);

    const ims = signify.d(signify.messagize(rpy, [sig]));

    const res = await alice.introduce().submit(bobAid.prefix, ims);
    console.log('Alice introduce res:', res);

}, 60000);
