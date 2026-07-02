import { Algos } from '../core/manager.ts';
import { Signer } from '../core/signer.ts';
import { Verfer } from '../core/verfer.ts';
import { Diger } from '../core/diger.ts';
import { Siger } from '../core/siger.ts';
import { Cigar } from '../core/cigar.ts';
import { MtrDex } from '../core/matter.ts';
import { IdrDex } from '../core/indexer.ts';
import {
    IdentifierManager,
    IdentifierManagerResult,
    SignResult,
} from '../core/keeping.ts';
import { KeyState } from '../core/keyState.ts';

export interface IExternalSigner {
    sign(msg: Uint8Array): Promise<Uint8Array>;
    pubKey(): Promise<Uint8Array>;
    nextPubKey(): Promise<Uint8Array>;
    rotate(): Promise<void>;
}

export class ExternSignerModule implements IdentifierManager {
    algo: Algos = Algos.extern;
    signers: Signer[] = [];

    // Registry of live IExternalSigner instances keyed by AID prefix.
    // KERIA cannot serialise a signer reference, so the HabState returned by
    // GET /identifiers/{pre} only carries {extern_type, pidx}. When signify-ts
    // rebuilds the manager from that HabState (e.g. inside addEndRole or any
    // other signing path), there's no signer in kargs. Hosts that own the
    // signer (e.g. a hardware wallet) must call registerSigner after the
    // create flow returns the AID prefix. The constructor falls back to this
    // registry when kargs.extern.signer is missing.
    private static _registry: Map<string, IExternalSigner> = new Map();

    static registerSigner(prefix: string, signer: IExternalSigner): void {
        ExternSignerModule._registry.set(prefix, signer);
    }

    static unregisterSigner(prefix: string): void {
        ExternSignerModule._registry.delete(prefix);
    }

    static getRegisteredSigner(prefix: string): IExternalSigner | undefined {
        return ExternSignerModule._registry.get(prefix);
    }

    private _signer: IExternalSigner;
    private _pidx: number;
    private _transferable: boolean;
    private _dcode: string;

    constructor(pidx: number, kargs: any, aid?: any) {
        const prefix = aid?.prefix ?? aid?.i;
        const fromKargs = kargs?.extern?.signer as IExternalSigner | undefined;
        const fromRegistry = prefix
            ? ExternSignerModule._registry.get(prefix)
            : undefined;
        this._pidx = pidx;
        const signer = fromKargs ?? fromRegistry;
        if (!signer) {
            throw new Error(
                'ExternSignerModule: no signer in kargs and none registered ' +
                    'for prefix=' +
                    prefix +
                    '. Call ExternSignerModule.registerSigner ' +
                    'after the extern AID is created.'
            );
        }
        this._signer = signer;
        this._transferable = kargs?.transferable ?? true;
        this._dcode = kargs?.dcode ?? MtrDex.Blake3_256;
    }

    params() {
        return { pidx: this._pidx, extern_type: 'keri-card' };
    }

    async incept(transferable: boolean): Promise<IdentifierManagerResult> {
        this._transferable = transferable;
        const code = transferable ? MtrDex.Ed25519 : MtrDex.Ed25519N;

        const pubBytes = await this._signer.pubKey();
        const verfer = new Verfer({ raw: pubBytes, code });

        const nextPubBytes = await this._signer.nextPubKey();
        const nextVerfer = new Verfer({ raw: nextPubBytes, code });
        const diger = new Diger({ code: this._dcode }, nextVerfer.qb64b);

        return [[verfer.qb64], [diger.qb64]];
    }

    async rotate(
        ncodes: string[],
        transferable: boolean,
        states?: KeyState[],
        rstates?: KeyState[]
    ): Promise<IdentifierManagerResult> {
        this._transferable = transferable;
        const code = transferable ? MtrDex.Ed25519 : MtrDex.Ed25519N;

        await this._signer.rotate();

        const pubBytes = await this._signer.pubKey();
        const verfer = new Verfer({ raw: pubBytes, code });

        const nextPubBytes = await this._signer.nextPubKey();
        const nextVerfer = new Verfer({ raw: nextPubBytes, code });
        const diger = new Diger({ code: this._dcode }, nextVerfer.qb64b);

        return [[verfer.qb64], [diger.qb64]];
    }

    async sign(
        ser: Uint8Array,
        indexed = true,
        indices?: number[],
        ondices?: Array<number | undefined>,
        rotated?: boolean
    ): Promise<SignResult> {
        const sig = await this._signer.sign(ser);

        if (indexed) {
            const i = indices?.[0] ?? 0;
            // For a rotation the new current key was the prior next at
            // ondex=i, so the siger must carry the ondex (same default as
            // SaltyKeeper). Inception stays current-only (ondex undefined).
            let o = ondices?.[0];
            if (o === undefined && rotated) {
                o = i;
            }
            const only = o === undefined;
            let code: string;
            if (only) {
                code =
                    i <= 63
                        ? IdrDex.Ed25519_Crt_Sig
                        : IdrDex.Ed25519_Big_Crt_Sig;
            } else {
                code =
                    o === i && i <= 63
                        ? IdrDex.Ed25519_Sig
                        : IdrDex.Ed25519_Big_Sig;
            }
            return [new Siger({ raw: sig, code, index: i, ondex: o }).qb64];
        } else {
            return [new Cigar({ raw: sig, code: MtrDex.Ed25519_Sig }).qb64];
        }
    }
}
