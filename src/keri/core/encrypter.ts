import libsodium from 'libsodium-wrappers-sumo';

import {ciXAllQB64Dex, ciXVarStrmDex, Matter, MatterArgs, MatterCodex, MtrDex} from './matter';
import { Verfer } from './verfer';
import { Signer } from './signer';
import { Cipher } from './cipher';
import { arrayEquals } from './utils';
import {Streamer} from "./streamer";

export class Encrypter extends Matter {
    private _encrypt: any;
    constructor(
        { raw, code = MtrDex.X25519, qb64, qb64b, qb2 }: MatterArgs,
        verkey: Uint8Array | null = null
    ) {
        if (raw == undefined && verkey != null) {
            const verfer = new Verfer({ qb64b: verkey });
            if (
                !Array.from([MtrDex.Ed25519N, MtrDex.Ed25519]).includes(
                    verfer.code
                )
            ) {
                throw new Error(
                    `Unsupported verkey derivation code = ${verfer.code}.`
                );
            }
            raw = libsodium.crypto_sign_ed25519_pk_to_curve25519(verfer.raw);
        }

        super({ raw, code, qb64, qb64b, qb2 });

        if (this.code == MtrDex.X25519) {
            this._encrypt = this._x25519;
        } else {
            throw new Error(`Unsupported encrypter code = ${this.code}.`);
        }
    }

    verifySeed(seed: Uint8Array) {
        const signer = new Signer({ qb64b: seed });
        const keypair = libsodium.crypto_sign_seed_keypair(signer.raw);
        const pubkey = libsodium.crypto_sign_ed25519_pk_to_curve25519(
            keypair.publicKey
        );
        return arrayEquals(pubkey, this.raw);
    }

    encrypt(ser: Uint8Array | null = null, matter: Matter | Streamer | null = null, code: string | null = null) {

        if (!ser) {
            if (!matter){
                throw new Error('Neither ser nor matter are provided.');
            }

            if (!code) {
                if (!(matter instanceof Matter) || matter.code == MtrDex.Salt_128){
                    code = MtrDex.X25519_Cipher_Salt;
                } else if (matter.code == MtrDex.Ed25519_Seed){
                    code = MtrDex.X25519_Cipher_Seed;
                } else {
                    throw new Error(`Unsupported primitive with code = ${matter.code} when cipher code is missing`);
                }
            }

            if (ciXAllQB64Dex.includes(code)) {
                if (matter instanceof Matter) {
                    ser = matter.qb64b;
                }
            } else if (ciXVarStrmDex.includes(code)){
                ser = (matter as Streamer).stream;
            } else {
                throw new Error(`Invalid primitive cipher ${(matter instanceof Matter) ? matter.code : matter.stream} not qb64`);
            }
        }

        if (!code) { // assumes default is sniffable stream
            code = MtrDex.X25519_Cipher_L0;
        }

        return this._encrypt(ser, this.raw, code);
    }

    _x25519(ser: Uint8Array, pubkey: Uint8Array, code: string) {
        const raw = libsodium.crypto_box_seal(ser, pubkey);
        return new Cipher({ raw: raw, code: code });
    }
}
