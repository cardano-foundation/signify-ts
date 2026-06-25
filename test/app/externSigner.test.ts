import { describe, it, expect, vi } from 'vitest';
import { ExternSignerModule, IExternalSigner } from '../../src/keri/app/externSigner.ts';
import { Verfer } from '../../src/keri/core/verfer.ts';
import { Diger } from '../../src/keri/core/diger.ts';
import { Siger } from '../../src/keri/core/siger.ts';
import { Cigar } from '../../src/keri/core/cigar.ts';
import { MtrDex } from '../../src/keri/core/matter.ts';
import { IdrDex } from '../../src/keri/core/indexer.ts';
import { Algos } from '../../src/keri/core/manager.ts';

const PUB  = new Uint8Array(32).fill(0x01);
const NEXT = new Uint8Array(32).fill(0x02);
const SIG  = new Uint8Array(64).fill(0x07);
const SER  = new Uint8Array(10).fill(0x42);

function makeMock(): IExternalSigner {
    return {
        sign:       vi.fn().mockResolvedValue(SIG),
        pubKey:     vi.fn().mockResolvedValue(PUB),
        nextPubKey: vi.fn().mockResolvedValue(NEXT),
        rotate:     vi.fn().mockResolvedValue(undefined),
    };
}

function makeModule(mock: IExternalSigner, transferable = true) {
    return new ExternSignerModule(0, {
        extern: { signer: mock },
        transferable,
    });
}

describe('ExternSignerModule', () => {
    describe('params()', () => {
        it('returns pidx and extern_type', () => {
            const m = makeModule(makeMock());
            expect(m.params()).toEqual({ pidx: 0, extern_type: 'keri-card' });
        });

        it('algo is extern', () => {
            expect(makeModule(makeMock()).algo).toBe(Algos.extern);
        });
    });

    describe('incept()', () => {
        it('returns verfer qb64 for current key, transferable', async () => {
            const mock = makeMock();
            const [verfers] = await makeModule(mock).incept(true);
            const expected = new Verfer({ raw: PUB, code: MtrDex.Ed25519 });
            expect(verfers[0]).toBe(expected.qb64);
        });

        it('uses Ed25519N code when non-transferable', async () => {
            const mock = makeMock();
            const [verfers] = await makeModule(mock, false).incept(false);
            const expected = new Verfer({ raw: PUB, code: MtrDex.Ed25519N });
            expect(verfers[0]).toBe(expected.qb64);
        });

        it('returns Blake3_256 diger for next key', async () => {
            const mock = makeMock();
            const [, digers] = await makeModule(mock).incept(true);
            const nextVerfer = new Verfer({ raw: NEXT, code: MtrDex.Ed25519 });
            const expected = new Diger({ code: MtrDex.Blake3_256 }, nextVerfer.qb64b);
            expect(digers[0]).toBe(expected.qb64);
        });

        it('calls pubKey and nextPubKey once each', async () => {
            const mock = makeMock();
            await makeModule(mock).incept(true);
            expect(mock.pubKey).toHaveBeenCalledOnce();
            expect(mock.nextPubKey).toHaveBeenCalledOnce();
        });
    });

    describe('rotate()', () => {
        it('calls rotate() on the signer before reading keys', async () => {
            const mock = makeMock();
            const order: string[] = [];
            (mock.rotate as any).mockImplementation(() => { order.push('rotate'); return Promise.resolve(); });
            (mock.pubKey as any).mockImplementation(() => { order.push('pubKey'); return Promise.resolve(PUB); });
            await makeModule(mock).rotate([], true);
            expect(order[0]).toBe('rotate');
        });

        it('returns new current verfer after rotation', async () => {
            const mock = makeMock();
            const [verfers] = await makeModule(mock).rotate([], true);
            const expected = new Verfer({ raw: PUB, code: MtrDex.Ed25519 });
            expect(verfers[0]).toBe(expected.qb64);
        });

        it('returns diger of new next key', async () => {
            const mock = makeMock();
            const [, digers] = await makeModule(mock).rotate([], true);
            const nextVerfer = new Verfer({ raw: NEXT, code: MtrDex.Ed25519 });
            const expected = new Diger({ code: MtrDex.Blake3_256 }, nextVerfer.qb64b);
            expect(digers[0]).toBe(expected.qb64);
        });
    });

    describe('sign() indexed', () => {
        it('returns Siger qb64 with Ed25519_Sig code when index==ondex and both<=63', async () => {
            const mock = makeMock();
            const result = await makeModule(mock).sign(SER, true, [0], [0]);
            const expected = new Siger({ raw: SIG, code: IdrDex.Ed25519_Sig, index: 0, ondex: 0 });
            expect(result[0]).toBe(expected.qb64);
        });

        it('uses Ed25519_Crt_Sig when ondex is undefined (only=true) and index<=63', async () => {
            const mock = makeMock();
            const result = await makeModule(mock).sign(SER, true, [0], undefined);
            const expected = new Siger({ raw: SIG, code: IdrDex.Ed25519_Crt_Sig, index: 0, ondex: undefined });
            expect(result[0]).toBe(expected.qb64);
        });

        it('uses Ed25519_Big_Crt_Sig when ondex is undefined and index>63', async () => {
            const mock = makeMock();
            const result = await makeModule(mock).sign(SER, true, [64], undefined);
            const expected = new Siger({ raw: SIG, code: IdrDex.Ed25519_Big_Crt_Sig, index: 64, ondex: undefined });
            expect(result[0]).toBe(expected.qb64);
        });

        it('uses Ed25519_Big_Sig when index!=ondex', async () => {
            const mock = makeMock();
            const result = await makeModule(mock).sign(SER, true, [1], [2]);
            const expected = new Siger({ raw: SIG, code: IdrDex.Ed25519_Big_Sig, index: 1, ondex: 2 });
            expect(result[0]).toBe(expected.qb64);
        });

        it('calls signer.sign with the full serialization', async () => {
            const mock = makeMock();
            await makeModule(mock).sign(SER, true);
            expect(mock.sign).toHaveBeenCalledWith(SER);
        });
    });

    describe('sign() unindexed', () => {
        it('returns Cigar qb64 with Ed25519_Sig matter code', async () => {
            const mock = makeMock();
            const result = await makeModule(mock).sign(SER, false);
            const expected = new Cigar({ raw: SIG, code: MtrDex.Ed25519_Sig });
            expect(result[0]).toBe(expected.qb64);
        });
    });
});
