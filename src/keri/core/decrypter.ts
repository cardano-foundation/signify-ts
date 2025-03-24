import libsodium from 'libsodium-wrappers-sumo';

import {ciXAllQB64Dex, ciXVarQB2Dex, ciXVarStrmDex, Matter, MatterArgs, MtrDex} from './matter';
import { Signer } from './signer';
import { Cipher } from './cipher';
import { EmptyMaterialError } from './kering';
import { Salter } from './salter';
import {Streamer} from "./streamer";

export class Decrypter extends Matter {
    private readonly _decrypt: any;
    constructor(
        { raw, code = MtrDex.X25519_Private, qb64, qb64b, qb2 }: MatterArgs,
        seed: Uint8Array | undefined = undefined
    ) {
        try {
            super({ raw, code, qb64, qb64b, qb2 });
        } catch (e) {
            if (e instanceof EmptyMaterialError) {
                if (seed != undefined) {
                    const signer = new Signer({ qb64b: seed });
                    if (signer.code != MtrDex.Ed25519_Seed) {
                        throw new Error(
                            `Unsupported signing seed derivation code ${signer.code}`
                        );
                    }
                    const sigkey = new Uint8Array(
                        signer.raw.length + signer.verfer.raw.length
                    );
                    sigkey.set(signer.raw);
                    sigkey.set(signer.verfer.raw, signer.raw.length);
                    raw =
                        libsodium.crypto_sign_ed25519_sk_to_curve25519(sigkey);
                    super({ raw, code, qb64, qb64b, qb2 });
                } else {
                    throw e;
                }
            } else {
                throw e;
            }
        }

        if (this.code == MtrDex.X25519_Private) {
            this._decrypt = this._x25519;
        } else {
            throw new Error(`Unsupported decrypter code = ${this.code}.`);
        }
    }

    decrypt(
        ser: Uint8Array | null = null, // qb64b
        cipher: Cipher | null = null,
        klas = null,
        transferable: boolean = false,
        bare: boolean = false
    ) {

        if (!cipher){
            if (ser != null) {
                cipher = new Cipher({ qb64b: ser });
            } else {
                throw new Error(`Need one of cipher or qb64`);
            }
        }

        return this._decrypt(cipher, this.raw, klas, transferable, bare);
    }

    _x25519(cipher: Cipher, prikey: Uint8Array, Klas?: typeof Matter | typeof Streamer, transferable: boolean = false, bare: boolean = false) {
        const pubkey = libsodium.crypto_scalarmult_base(prikey);
        const plain = libsodium.crypto_box_seal_open(
            cipher.raw,
            pubkey,
            prikey
        );

        if (bare) {
            return plain
        } else {
            if (!Klas) {
                if (cipher.code === MtrDex.X25519_Cipher_Salt){
                    Klas = Salter;
                } else if (cipher.code === MtrDex.X25519_Cipher_Seed) {
                    Klas = Signer;
                } else if (ciXVarStrmDex.includes(cipher.code)){
                    Klas = Streamer;
                } else {
                    throw new Error(`Unsupported cipher code = ${cipher.code} when klas missing.`);
                }
            }

            if (ciXAllQB64Dex.includes(cipher.code)) {
                // @ts-ignore
                return new Klas({qb64b: plain, transferable});
            } else if (ciXVarStrmDex.includes(cipher.code)){
                // @ts-ignore
                return new Klas(plain)
            } else {
                throw new Error(`Unsupported cipher code = ${cipher.code}.`);
            }
        }
    }
}
