import { Matter, MatterArgs, MtrDex } from './matter';
import { Decrypter } from './decrypter';

export class Cipher extends Matter {
    constructor({ raw, code, qb64, qb64b, qb2 }: MatterArgs) {
        if (raw != undefined && code == undefined) {
            if (raw.length == Matter._rawSize(MtrDex.X25519_Cipher_Salt)) {
                code = MtrDex.X25519_Cipher_Salt;
            } else if (
                raw.length == Matter._rawSize(MtrDex.X25519_Cipher_Seed)
            ) {
                code = MtrDex.X25519_Cipher_Salt;
            }
        }
        super({ raw: raw, code: code, qb64b: qb64b, qb64: qb64, qb2: qb2 });

        if (!this.code || ![
            MtrDex.X25519_Cipher_Salt, MtrDex.X25519_Cipher_Seed,
            MtrDex.X25519_Cipher_L0, MtrDex.X25519_Cipher_L1, MtrDex.X25519_Cipher_L2,
            MtrDex.X25519_Cipher_Big_L0, MtrDex.X25519_Cipher_Big_L1, MtrDex.X25519_Cipher_Big_L2,
            MtrDex.X25519_Cipher_QB64_L0, MtrDex.X25519_Cipher_QB64_L1, MtrDex.X25519_Cipher_QB64_L2,
            MtrDex.X25519_Cipher_QB64_Big_L0, MtrDex.X25519_Cipher_QB64_Big_L1, MtrDex.X25519_Cipher_QB64_Big_L2,
            MtrDex.X25519_Cipher_QB2_L0, MtrDex.X25519_Cipher_QB2_L1, MtrDex.X25519_Cipher_QB2_L2,
            MtrDex.X25519_Cipher_QB2_Big_L0, MtrDex.X25519_Cipher_QB2_Big_L1, MtrDex.X25519_Cipher_QB2_Big_L2
        ].includes(this.code)) {
            throw new Error(`Unsupported Cipher code == ${this.code}`);
        }
    }

    decrypt(
        prikey: Uint8Array | undefined = undefined,
        seed: Uint8Array | undefined = undefined
    ) {
        const decrypter = new Decrypter({ qb64b: prikey }, seed);
        return decrypter.decrypt(this.qb64b);
    }
}
