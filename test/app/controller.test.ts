import { Controller } from '../../src/keri/app/controller.ts';
import { assert, describe, expect, it, vi } from 'vitest';
import libsodium from 'libsodium-wrappers-sumo';
import { openManager } from '../../src/keri/core/manager.ts';
import { Salter } from '../../src/keri/core/salter.ts';
import { Signer } from '../../src/keri/core/signer.ts';
import { Verfer } from '../../src/keri/core/verfer.ts';
import { Diger } from '../../src/keri/core/diger.ts';
import { Cipher } from '../../src/keri/core/cipher.ts';
import { Encrypter } from '../../src/keri/core/encrypter.ts';
import { Decrypter } from '../../src/keri/core/decrypter.ts';
import { MtrDex } from '../../src/keri/core/matter.ts';
import { Tier, randomPasscode, b } from '../../src/index.ts';

describe('Controller', () => {
    it('manage account AID signing and agent verification', async () => {
        await libsodium.ready;
        let passcode = '0123456789abcdefghijk';
        const mgr = openManager(passcode);
        assert.equal(mgr.aeid, 'BMbZTXzB7LmWPT2TXLGV88PQz5vDEM2L2flUs2yxn3U9');

        const raw = new Uint8Array([
            187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192,
            61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87, 143, 109, 39, 98,
            153, 192, 148,
        ]);
        const agentSigner = new Signer({
            raw: raw,
            code: MtrDex.Ed25519_Seed,
            transferable: false,
        });
        assert.equal(
            agentSigner.verfer.qb64,
            'BHptu91ecGv_mxO8T3b98vNQUCghT8nfYkWRkVqOZark'
        );

        // New account needed.  Send to remote my name and encryption pubk and get back
        // their pubk and and my encrypted account package
        // let pkg = {}
        let controller = new Controller(passcode, Tier.low);
        assert.equal(
            controller.pre,
            'ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose'
        );

        passcode = 'abcdefghijk0123456789';
        controller = new Controller(passcode, Tier.low);
        assert.equal(
            controller.pre,
            'EIIY2SgE_bqKLl2MlnREUawJ79jTuucvWwh-S6zsSUFo'
        );
    });

    it('should generate unique controller AIDs per passcode', async () => {
        await libsodium.ready;
        const passcode1 = randomPasscode();
        const passcode2 = randomPasscode();

        const controller1 = new Controller(passcode1, Tier.low);
        const controller2 = new Controller(passcode2, Tier.low);

        assert.notEqual(controller1.pre, controller2.pre);
    });

    describe('setExternalNext', () => {
        // Build a Signer/Verfer pair to act as the "card key" the host
        // wants to commit as next.
        function makeCardKey() {
            const raw = new Uint8Array(32).fill(0x42);
            const signer = new Signer({ raw, code: MtrDex.Ed25519_Seed });
            const ndig = new Diger(
                { code: MtrDex.Blake3_256 },
                signer.verfer.qb64b
            ).qb64;
            return { signer, pubQb64: signer.verfer.qb64, ndig };
        }

        it('rebuilds the inception serder with the override ndigs', async () => {
            await libsodium.ready;
            const ctrl = new Controller(randomPasscode(), Tier.low);
            const { ndig } = makeCardKey();
            const beforePre = ctrl.pre;

            ctrl.setExternalNext([ndig]);

            assert.deepEqual(ctrl.ndigs, [ndig]);
            assert.deepEqual(ctrl.serder.sad.n, [ndig]);
            // The prefix changes because the inception event's digest
            // now includes the new n.
            assert.notEqual(ctrl.pre, beforePre);
            assert.equal(ctrl.serder.sad.t, 'icp');
        });

        it('throws when ridx > 0 (override only allowed at incept)', async () => {
            await libsodium.ready;
            const ctrl = new Controller(randomPasscode(), Tier.low);
            ctrl.ridx = 1;
            const { ndig } = makeCardKey();

            assert.throws(() => ctrl.setExternalNext([ndig]), /already rotated/);
        });

        it('throws when ndigs is empty', async () => {
            await libsodium.ready;
            const ctrl = new Controller(randomPasscode(), Tier.low);
            assert.throws(() => ctrl.setExternalNext([]), /ndigs required/);
        });
    });

    describe('rotateForRecovery', () => {
        // Build a fixture controller, a card signer to play the role of
        // the previously committed next-key, and helpers to construct
        // encrypted material for salty / randy / extern AIDs.
        function makeFixture() {
            const ctrlBran = '0123456789abcdefghijk';
            const ctrl = new Controller(ctrlBran, Tier.low);

            // Two distinct card signers: cardCur acts as the priv that
            // decrypts the OLD sxlt (= the previously committed next-key
            // KERIA encrypted under). cardNext is the new next-key the
            // host wants to commit in this rotation.
            const cardCurRaw = new Uint8Array(32).fill(0x55);
            const cardCur = new Signer({
                raw: cardCurRaw,
                code: MtrDex.Ed25519_Seed,
            });
            const cardNextRaw = new Uint8Array(32).fill(0x77);
            const cardNext = new Signer({
                raw: cardNextRaw,
                code: MtrDex.Ed25519_Seed,
            });

            return { ctrl, cardCur, cardNext, nbran: 'abcdefghijklmnopqrstu' };
        }

        function encryptForCard(plain: Uint8Array, cardPubQb64: string): string {
            const enc = new Encrypter({}, b(cardPubQb64));
            return enc.encrypt(plain).qb64;
        }

        it('builds dual-key rot: k=[new bran, cardCur], threshold [1,0], n=[H(cardNext)]', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();
            const expectedNdig = new Diger(
                { code: MtrDex.Blake3_256 },
                cardNext.verfer.qb64b
            ).qb64;

            const decryptOld = vi.fn();
            const signRot = vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xAA));

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                [], // no AIDs to migrate
                decryptOld,
                signRot
            );

            // Dual-key shape: [new bran current, cardCur revealed as old next].
            const k = (body.rot as any).k as string[];
            expect(k.length).toBe(2);
            const newSignerVerfer = new Verfer({ qb64: k[0] });
            assert.equal(newSignerVerfer.code, MtrDex.Ed25519);
            assert.equal(k[1], cardCur.verfer.qb64);
            assert.deepEqual((body.rot as any).kt, ['1', '0']);

            assert.deepEqual((body.rot as any).n, [expectedNdig]);
            assert.equal((body.rot as any).t, 'rot');
        });

        it('forwards rot.raw to signRot once; produces two sigs (new bran at 0, card at 1)', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();
            const sigBytes = new Uint8Array(64).fill(0xBB);
            const signRot = vi.fn().mockResolvedValue(sigBytes);
            const decryptOld = vi.fn();

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                [],
                decryptOld,
                signRot
            );

            expect(signRot).toHaveBeenCalledTimes(1);
            const callArg = signRot.mock.calls[0][0] as Uint8Array;
            assert.ok(callArg instanceof Uint8Array);
            assert.ok(callArg.length > 0);

            // Two sigs: new bran's signer at index 0 (code A), card sig at
            // index 1 ondex 0 (code 2A, the big-sig indexer).
            assert.equal(body.sigs.length, 2);
            assert.ok(body.sigs[0].startsWith('AA'));
            assert.ok(body.sigs[1].startsWith('2A'));
        });

        it('re-encrypts salty sxlt by calling decryptOld once per AID then encrypting under nextCardPub', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();

            // The plaintext we put through the round-trip must be a valid
            // qb64 matter — that's what Encrypter parses. A Salter qb64
            // is the natural fit (it's what real KERIA sxlts decrypt to).
            const plainSalter = new Salter({
                raw: new Uint8Array(16).fill(0x33),
            });
            const plaintext = b(plainSalter.qb64);
            const oldSxlt = encryptForCard(plaintext, cardCur.verfer.qb64);
            const aids = [
                {
                    prefix: 'EAlice___________________________________01',
                    salty: { sxlt: oldSxlt },
                },
            ];

            // Decrypt callback: this is what the wallet wires to the
            // card + libsodium. In test we just decrypt using cardCur's
            // priv via the standard Decrypter to mimic what the card
            // would return.
            const decryptOld = vi.fn(async (cipherQb64: string) => {
                const dec = new Decrypter({}, cardCur.qb64b);
                return b(dec.decrypt(null, new Cipher({ qb64: cipherQb64 })).qb64);
            });
            const signRot = vi.fn().mockResolvedValue(new Uint8Array(64));

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                aids,
                decryptOld,
                signRot
            );

            expect(decryptOld).toHaveBeenCalledTimes(1);
            expect(decryptOld).toHaveBeenCalledWith(oldSxlt);

            const newKey = body.keys[aids[0].prefix];
            assert.ok(newKey?.sxlt, 'expected new salty sxlt in body');
            assert.notEqual(newKey.sxlt, oldSxlt);

            // And the new sxlt round-trips: decrypt it with cardNext's
            // priv and verify the original plaintext is recovered.
            const dec = new Decrypter({}, cardNext.qb64b);
            const recovered = dec.decrypt(null, new Cipher({ qb64: newKey.sxlt })).qb64;
            assert.deepEqual(b(recovered), plaintext);
        });

        it('re-encrypts randy AIDs by decrypting every prxs and nxts blob', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();

            // Same constraint as the salty test: the plaintexts must be
            // valid qb64 matter. Use Salter qb64s for the prxs/nxts
            // fixtures (they stand in for encrypted signer seeds).
            const mkSalt = (fill: number) =>
                new Salter({ raw: new Uint8Array(16).fill(fill) }).qb64;
            const prxsPlain = [b(mkSalt(0xA1)), b(mkSalt(0xA2))];
            const nxtsPlain = [b(mkSalt(0xB1))];
            const aids = [
                {
                    prefix: 'EBob_____________________________________02',
                    randy: {
                        prxs: prxsPlain.map((p) => encryptForCard(p, cardCur.verfer.qb64)),
                        nxts: nxtsPlain.map((p) => encryptForCard(p, cardCur.verfer.qb64)),
                    },
                },
            ];

            const decryptOld = vi.fn(async (cipherQb64: string) => {
                const dec = new Decrypter({}, cardCur.qb64b);
                return b(dec.decrypt(null, new Cipher({ qb64: cipherQb64 })).qb64);
            });
            const signRot = vi.fn().mockResolvedValue(new Uint8Array(64));

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                aids,
                decryptOld,
                signRot
            );

            // One call per prxs (2) + one per nxts (1) = 3 total
            expect(decryptOld).toHaveBeenCalledTimes(3);
            const newKey = body.keys[aids[0].prefix];
            assert.equal(newKey.prxs.length, 2);
            assert.equal(newKey.nxts.length, 1);

            // Round-trip each new blob through cardNext priv.
            const dec = new Decrypter({}, cardNext.qb64b);
            for (let i = 0; i < newKey.prxs.length; i++) {
                const recovered = dec.decrypt(null, new Cipher({ qb64: newKey.prxs[i] })).qb64;
                assert.deepEqual(b(recovered), prxsPlain[i]);
            }
            for (let i = 0; i < newKey.nxts.length; i++) {
                const recovered = dec.decrypt(null, new Cipher({ qb64: newKey.nxts[i] })).qb64;
                assert.deepEqual(b(recovered), nxtsPlain[i]);
            }
        });

        it('skips extern AIDs (no decrypt calls, no entry in keys)', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();
            const aids = [
                {
                    prefix: 'ECarol___________________________________03',
                    extern: { extern_type: 'keri-card', pidx: 1 },
                },
            ];

            const decryptOld = vi.fn();
            const signRot = vi.fn().mockResolvedValue(new Uint8Array(64));

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                aids,
                decryptOld,
                signRot
            );

            expect(decryptOld).not.toHaveBeenCalled();
            assert.equal(
                Object.prototype.hasOwnProperty.call(body.keys, aids[0].prefix),
                false
            );
        });

        // The retrofit path: rotate a wallet that wasn't created with a
        // recovery card to commit one as the new next-key.
        describe('rotateWithExternalNext (retrofit)', () => {
            it('throws when nextOverride is empty', async () => {
                await libsodium.ready;
                const { ctrl } = makeFixture();
                assert.throws(
                    () => ctrl.rotateWithExternalNext('abcdefghijk0123456789', [], []),
                    /nextOverride required/
                );
            });

            it('builds rot with dual-key shape and the override digest as n', async () => {
                await libsodium.ready;
                const { ctrl, cardCur, nbran } = makeFixture();
                const overrideDigest = new Diger(
                    { code: MtrDex.Blake3_256 },
                    cardCur.verfer.qb64b
                ).qb64;

                const body: any = ctrl.rotateWithExternalNext(nbran, [], [
                    overrideDigest,
                ]);

                // Dual-key shape preserved: two keys, threshold ['1','0'].
                assert.equal((body.rot as any).t, 'rot');
                assert.equal((body.rot as any).k.length, 2);
                assert.deepEqual((body.rot as any).kt, ['1', '0']);

                // n is the host override exactly.
                assert.deepEqual((body.rot as any).n, [overrideDigest]);

                // Two sigs (matches the dual-key shape KERIA expects).
                assert.equal(body.sigs.length, 2);
            });

            it('produces a top-level sxlt and persists the new ndigs/serder', async () => {
                await libsodium.ready;
                const { ctrl, cardNext, nbran } = makeFixture();
                const overrideDigest = new Diger(
                    { code: MtrDex.Blake3_256 },
                    cardNext.verfer.qb64b
                ).qb64;

                const body: any = ctrl.rotateWithExternalNext(nbran, [], [
                    overrideDigest,
                ]);

                // Top-level sxlt comes from the wrapped rotate() and
                // travels through unchanged.
                assert.ok(
                    typeof body.sxlt === 'string' && body.sxlt.length > 0,
                    'expected top-level sxlt'
                );
                // Internal state reflects the override and the rotation.
                // Note: standard rotate() doesn't auto-increment ridx,
                // so we don't check it here.
                assert.deepEqual(ctrl.ndigs, [overrideDigest]);
                assert.equal(ctrl.serder.sad.t, 'rot');
            });
        });

        it('aeidUnderNewBran: sxlt decrypts under new bran signer; n[] stays card-bound', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();

            const plainSalter = new Salter({
                raw: new Uint8Array(16).fill(0x44),
            });
            const plaintext = b(plainSalter.qb64);
            // Old sxlt encrypted under cardCur (the previously committed next-key).
            const enc = new Encrypter({}, b(cardCur.verfer.qb64));
            const oldSxlt = enc.encrypt(plaintext).qb64;
            const aids = [
                {
                    prefix: 'EDave____________________________________04',
                    salty: { sxlt: oldSxlt },
                },
            ];

            const decryptOld = vi.fn(async (cipherQb64: string) => {
                const dec = new Decrypter({}, cardCur.qb64b);
                return b(dec.decrypt(null, new Cipher({ qb64: cipherQb64 })).qb64);
            });
            const signRot = vi.fn().mockResolvedValue(new Uint8Array(64).fill(0xCC));

            const body = await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                aids,
                decryptOld,
                signRot,
                { aeidUnderNewBran: true }
            );

            // Derive what the new bran's aeid signer is (mirrors controller internals).
            const newBranQb64 = MtrDex.Salt_128 + 'A' + nbran.substring(0, 21);
            const newSalter = new Salter({ qb64: newBranQb64 });
            const newBranSigner = newSalter.signer(MtrDex.Ed25519_Seed, true, '', Tier.low);

            // The per-AID sxlt must decrypt under the new bran signer, not cardNext.
            const dec = new Decrypter({}, newBranSigner.qb64b);
            const recovered = dec.decrypt(null, new Cipher({ qb64: body.keys[aids[0].prefix].sxlt })).qb64;
            assert.deepEqual(b(recovered), plaintext, 'sxlt must decrypt under new bran signer');

            // Top-level sxlt also decrypts under the new bran signer.
            const recoveredTop = dec.decrypt(null, new Cipher({ qb64: body.sxlt })).qb64;
            assert.equal(recoveredTop, newBranQb64, 'top-level sxlt must encrypt the new bran');

            // n[] must still commit the card next-pub (card-bound).
            const expectedNdig = new Diger(
                { code: MtrDex.Blake3_256 },
                cardNext.verfer.qb64b
            ).qb64;
            assert.deepEqual((body.rot as any).n, [expectedNdig]);
            // And k[1] is the cardCur verfer (revealed old next).
            assert.equal((body.rot as any).k[1], cardCur.verfer.qb64);
        });

        it('mutates this.bran, this.signer, this.ndigs, this.serder, and this.ridx', async () => {
            await libsodium.ready;
            const { ctrl, cardCur, cardNext, nbran } = makeFixture();
            const beforeRidx = ctrl.ridx;
            const beforeSerderD = ctrl.serder.sad.d;
            const beforeSigner = ctrl.signer;

            const expectedNbran =
                MtrDex.Salt_128 + 'A' + nbran.substring(0, 21);
            const expectedNdig = new Diger(
                { code: MtrDex.Blake3_256 },
                cardNext.verfer.qb64b
            ).qb64;

            await ctrl.rotateForRecovery(
                nbran,
                cardCur.verfer.qb64,
                cardNext.verfer.qb64,
                [],
                vi.fn(),
                vi.fn().mockResolvedValue(new Uint8Array(64))
            );

            // `bran` is private — narrow via cast for the assertion.
            assert.equal((ctrl as any).bran, expectedNbran);
            assert.notEqual(ctrl.signer, beforeSigner);
            assert.deepEqual(ctrl.ndigs, [expectedNdig]);
            assert.equal(ctrl.serder.sad.t, 'rot');
            assert.notEqual(ctrl.serder.sad.d, beforeSerderD);
            assert.equal(ctrl.ridx, beforeRidx + 1);
        });
    });
});
