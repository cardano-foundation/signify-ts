import { SaltyCreator } from '../core/manager.ts';
import { Salter, Tier } from '../core/salter.ts';
import { MtrDex } from '../core/matter.ts';
import { Diger } from '../core/diger.ts';
import { incept, rotate, interact } from '../core/eventing.ts';
import { Serder } from '../core/serder.ts';
import { Tholder } from '../core/tholder.ts';
import { Ilks, b, Serials, Vrsn_1_0 } from '../core/core.ts';
import { Verfer } from '../core/verfer.ts';
import { Encrypter } from '../core/encrypter.ts';
import { Decrypter } from '../core/decrypter.ts';
import { Cipher } from '../core/cipher.ts';
import { Seqner } from '../core/seqner.ts';
import { CesrNumber } from '../core/number.ts';
import { Siger } from '../core/siger.ts';
import { IdrDex } from '../core/indexer.ts';

/**
 * Agent is a custodial entity that can be used in conjuntion with a local Client to establish the
 * KERI "signing at the edge" semantic
 */
export class Agent {
    pre: string;
    anchor: string;
    verfer: Verfer | null;
    state: any | null;
    sn: number | undefined;
    said: string | undefined;

    constructor(agent: any) {
        this.pre = '';
        this.anchor = '';
        this.verfer = null;
        this.state = null;
        this.sn = 0;
        this.said = '';
        this.parse(agent);
    }

    private parse(agent: Agent) {
        const [state, verfer] = this.event(agent);

        this.sn = new CesrNumber({}, state['s']).num;
        this.said = state['d'];

        if (state['et'] !== Ilks.dip) {
            throw new Error(`invalid inception event type ${state['et']}`);
        }

        this.pre = state['i'];
        if (!state['di']) {
            throw new Error('no anchor to controller AID');
        }

        this.anchor = state['di'];

        this.verfer = verfer;
        this.state = state;
    }

    private event(evt: any): [any, Verfer, Diger] {
        if (evt['k'].length !== 1) {
            throw new Error(`agent inception event can only have one key`);
        }

        const verfer = new Verfer({ qb64: evt['k'][0] });

        if (evt['n'].length !== 1) {
            throw new Error(`agent inception event can only have one next key`);
        }

        const diger = new Diger({ qb64: evt['n'][0] });

        const tholder = new Tholder({ sith: evt['kt'] });
        if (tholder.num !== 1) {
            throw new Error(`invalid threshold ${tholder.num}, must be 1`);
        }

        const ntholder = new Tholder({ sith: evt['nt'] });
        if (ntholder.num !== 1) {
            throw new Error(
                `invalid next threshold ${ntholder.num}, must be 1`
            );
        }
        return [evt, verfer, diger];
    }
}

/**
 * Controller is responsible for managing signing keys for the client and agent.  The client
 * signing key represents the Account for the client on the agent
 */
export class Controller {
    /*
    The bran is the combination of the first 21 characters of the passcode passed in prefixed with 'A' and '0A'.
    Looks like: '0A' + 'A' + 'thisismysecretkeyseed'
    Or: "0AAthisismysecretkeyseed"

    This is interpreted as encoded Base64URLSafe characters when used as the salt for key generation.
     */
    private bran: string;
    /**
     * The stem is the prefix for the stretched input bytes the controller's cryptographic
     * key pairs are derived from.
     */
    public stem: string;
    /**
     * The security tier for the identifiers created by this Controller.
     */
    public tier: Tier;
    /**
     * The rotation index used during key generation by this Controller.
     */
    public ridx: number;
    /**
     * The salter is a cryptographic salt used to derive the controller's cryptographic key pairs
     * and is deterministically derived from the bran and the security tier.
     */
    public salter: any;
    /**
     * The current signing key used to sign requests for this controller.
     */
    public signer: any;
    /**
     * The next signing key of which a digest is committed to in an establishment event (inception or rotation) to become the
     * signing key after the next rotation.
     * @private
     */
    private nsigner: any;
    /**
     * Either the current establishment event, inception or rotation, or the interaction event used for delegation approval.
     */
    public serder: Serder;
    /**
     * Current public keys formatted in fully-qualified Base64.
     * @private
     */
    private keys: string[];
    /**
     * Digests of the next public keys formatted in fully-qualified Base64.
     */
    public ndigs: string[];
    /**
     * Witness prefixes for this controller's establishment events. Set
     * via setExternalNext (or the constructor) before .boot() to thread
     * receipts through the chosen witness pool, then preserved across
     * rotations so rotateForRecovery emits a rot with the right `bt`.
     */
    public wits: string[] = [];
    /**
     * Threshold of accountable duplicity (numeric). Mirrors the prior
     * establishment event so the recovery rot's `bt` keeps matching.
     */
    public toad: number = 0;

    /**
     * Creates a Signify Controller starting at key index 0 that generates keys in
     * memory based on the provided seed, or bran, the tier, and the rotation index.
     *
     * The rotation index is used as follows:
     *
     * @param bran
     * @param tier
     * @param ridx
     * @param state
     */
    constructor(
        bran: string,
        tier: Tier,
        ridx: number = 0,
        state: any | null = null
    ) {
        this.bran = MtrDex.Salt_128 + 'A' + bran.substring(0, 21); // qb64 salt for seed
        this.stem = 'signify:controller';
        this.tier = tier;
        this.ridx = ridx;
        const codes = undefined; // Defines the types of seeds that the SaltyCreator will create. Defaults to undefined.
        const keyCount = 1; // The number of keys to create. Defaults to 1.
        const transferable = true; // Whether the keys are transferable. Defaults to true.
        const code = MtrDex.Ed25519_Seed; // The type  cryptographic seed to create by default when not overiddeen by "codes".
        const pidx = 0; // The index of this identifier prefix of all managed identifiers created for this SignifyClient Controller. Defaults to 0.
        const kidx = 0; // The overall starting key index for the first key this rotation set of keys. This is not a local index to this set of keys but an index in the overall set of keys for all keys in this sequence.
        // Defaults to 0. Multiply rotation index (ridx) times key count to get the overall key index.

        this.salter = new Salter({ qb64: this.bran, tier: this.tier });

        const creator = new SaltyCreator(
            this.salter.qb64,
            this.tier,
            this.stem
        );

        // Creates the first key pair used to sign the inception event.
        // noinspection UnnecessaryLocalVariableJS
        const initialKeyIndex = ridx; // will be zero for inception
        this.signer = creator
            .create(
                codes,
                keyCount,
                code,
                transferable,
                pidx,
                initialKeyIndex,
                kidx
            )
            .signers.pop(); // assumes only one key pair is created because keyCount is 1

        // Creates the second key pair which a digest of the public key is committed to in the inception event.
        const nextKeyIndex = ridx + 1;
        this.nsigner = creator
            .create(
                codes,
                keyCount,
                code,
                transferable,
                pidx,
                nextKeyIndex,
                kidx
            )
            .signers.pop(); // assumes only one key pair is created because keyCount is 1
        this.keys = [this.signer.verfer.qb64];
        this.ndigs = [
            new Diger({ code: MtrDex.Blake3_256 }, this.nsigner.verfer.qb64b)
                .qb64,
        ];

        if (state == null) {
            this.serder = incept({
                keys: this.keys,
                isith: '1',
                nsith: '1',
                ndigs: this.ndigs,
                code: MtrDex.Blake3_256,
                toad: this.toad,
                wits: this.wits,
            });
        } else {
            // Always mirror the establishment event KERIA already has,
            // including the inception (s==0) case. Rebuilding a fresh
            // local incept here would lose any external override applied
            // before boot (e.g. setExternalNext for the BioCard recovery
            // flow, where n[0] is committed to the card pub instead of
            // the bran-derived next-key).
            this.serder = new Serder(state['ee']);
            if (state['ee']['n']) {
                this.ndigs = state['ee']['n'];
            }
            // Restore wits/toad from KERIA's current key state if it
            // exposed them. The rot's `bt` chains to the prior `b` set,
            // so rotateForRecovery needs these to survive a connect.
            const kstate = state['state'];
            if (kstate && Array.isArray(kstate['b'])) {
                this.wits = kstate['b'];
            }
            if (kstate && kstate['bt'] !== undefined) {
                const btRaw = kstate['bt'];
                this.toad =
                    typeof btRaw === 'string' ? parseInt(btRaw, 16) : btRaw;
            }
        }
    }

    approveDelegation(_agent: Agent) {
        const seqner = new Seqner({ sn: _agent.sn });
        const anchor = { i: _agent.pre, s: seqner.snh, d: _agent.said };
        const sn = new CesrNumber({}, this.serder.sad['s']).num + 1;
        this.serder = interact({
            pre: this.serder.pre,
            dig: this.serder.sad['d'],
            sn: sn,
            data: [anchor],
            version: Vrsn_1_0,
            kind: Serials.JSON,
        });
        return [this.signer.sign(this.serder.raw, 0).qb64];
    }

    get pre(): string {
        return this.serder.pre;
    }

    get event() {
        const siger = this.signer.sign(this.serder.raw, 0);
        return [this.serder, siger];
    }

    get verfers(): [] {
        return this.signer.verfer();
    }

    derive(state: any) {
        if (state != undefined && state['ee']['s'] === '0') {
            return incept({
                keys: this.keys,
                isith: '1',
                nsith: '1',
                ndigs: this.ndigs,
                code: MtrDex.Blake3_256,
                toad: '0',
                wits: [],
            });
        } else {
            return new Serder({ sad: state.controller['ee'] });
        }
    }

    rotate(bran: string, aids: Array<any>) {
        const nbran = MtrDex.Salt_128 + 'A' + bran.substring(0, 21); // qb64 salt for seed
        const nsalter = new Salter({ qb64: nbran, tier: this.tier });
        const nsigner = this.salter.signer(undefined, false);

        const creator = new SaltyCreator(
            this.salter.qb64,
            this.tier,
            this.stem
        );
        const signer = creator
            .create(
                undefined,
                1,
                MtrDex.Ed25519_Seed,
                true,
                0,
                this.ridx + 1,
                0,
                false
            )
            .signers.pop();

        const ncreator = new SaltyCreator(nsalter.qb64, this.tier, this.stem);
        this.signer = ncreator
            .create(
                undefined,
                1,
                MtrDex.Ed25519_Seed,
                true,
                0,
                this.ridx,
                0,
                false
            )
            .signers.pop();
        this.nsigner = ncreator
            .create(
                undefined,
                1,
                MtrDex.Ed25519_Seed,
                true,
                0,
                this.ridx + 1,
                0,
                false
            )
            .signers.pop();

        this.keys = [this.signer.verfer.qb64, signer?.verfer.qb64];
        this.ndigs = [new Diger({}, this.nsigner.verfer.qb64b).qb64];

        const rot = rotate({
            pre: this.pre,
            keys: this.keys,
            dig: this.serder.sad['d'],
            isith: ['1', '0'],
            nsith: '1',
            ndigs: this.ndigs,
        });

        const sigs = [
            signer?.sign(b(rot.raw), 1, false, 0).qb64,
            this.signer.sign(rot.raw, 0).qb64,
        ];
        const encrypter = new Encrypter({}, b(nsigner.verfer.qb64));
        const decrypter = new Decrypter({}, nsigner.qb64b);
        const sxlt = encrypter.encrypt(b(this.bran)).qb64;

        const keys: Record<any, any> = {};

        for (const aid of aids) {
            const pre: string = aid['prefix'] as string;
            if ('salty' in aid) {
                const salty: any = aid['salty'];
                const cipher = new Cipher({ qb64: salty['sxlt'] });
                const dnxt = decrypter.decrypt(null, cipher).qb64;

                // Now we have the AID salt, use it to verify against the current public keys
                const acreator = new SaltyCreator(
                    dnxt,
                    salty['tier'],
                    salty['stem']
                );
                const signers = acreator.create(
                    salty['icodes'],
                    undefined,
                    MtrDex.Ed25519_Seed,
                    salty['transferable'],
                    salty['pidx'],
                    0,
                    salty['kidx'],
                    false
                );
                const _signers = [];
                for (const signer of signers.signers) {
                    _signers.push(signer.verfer.qb64);
                }
                const pubs = aid['state']['k'];

                if (pubs.join(',') != _signers.join(',')) {
                    throw new Error('Invalid Salty AID');
                }

                const asxlt = encrypter.encrypt(b(dnxt)).qb64;
                keys[pre] = {
                    sxlt: asxlt,
                };
            } else if ('randy' in aid) {
                const randy = aid['randy'];
                const prxs = randy['prxs'];
                const nxts = randy['nxts'];

                const nprxs = [];
                const signers = [];
                for (const prx of prxs) {
                    const cipher = new Cipher({ qb64: prx });
                    const dsigner = decrypter.decrypt(null, cipher, true);
                    signers.push(dsigner);
                    nprxs.push(encrypter.encrypt(b(dsigner.qb64)).qb64);
                }
                const pubs = aid['state']['k'];
                const _signers = [];
                for (const signer of signers) {
                    _signers.push(signer.verfer.qb64);
                }

                if (pubs.join(',') != _signers.join(',')) {
                    throw new Error(
                        `unable to rotate, validation of encrypted public keys ${pubs} failed`
                    );
                }

                const nnxts = [];
                for (const nxt of nxts) {
                    nnxts.push(this.recrypt(nxt, decrypter, encrypter));
                }

                keys[pre] = {
                    prxs: nprxs,
                    nxts: nnxts,
                };
            } else {
                throw new Error('invalid aid type ');
            }
        }

        const data = {
            rot: rot.sad,
            sigs: sigs,
            sxlt: sxlt,
            keys: keys,
        };
        return data;
    }

    recrypt(enc: string, decrypter: Decrypter, encrypter: Encrypter) {
        const cipher = new Cipher({ qb64: enc });
        const dnxt = decrypter.decrypt(null, cipher).qb64;
        return encrypter.encrypt(b(dnxt)).qb64;
    }

    /**
     * Build a controller rotation event whose new current key is
     * bran-derived (a brand new bran on a brand new phone) but whose
     * signing comes from an external signer (the BioCard) holding the
     * previously committed next-key.
     *
     * This is the recovery-from-card flow. Standard {@link rotate} can't
     * cover it because:
     *   - The old bran is gone (phone was lost)
     *   - The signature must be produced by the previously-committed-next
     *     key, which lives on the card
     *   - The old AID sxlt blobs are encrypted under that same card-held
     *     key, so the card must decrypt them via X25519 ECDH callback
     *   - The new sxlt blobs must be encrypted under the NEXT card pub
     *     (chosen by the host so the chain keeps going for the next
     *     recovery)
     *
     * Returns the body ready to PUT against /agent/{caid} and mutates
     * this.bran, this.signer, this.nsigner, this.serder and this.ridx to
     * reflect the rotated state.
     */
    async rotateForRecovery(
        nbran: string,
        cardPubQb64: string,
        nextCardPubQb64: string,
        aids: Array<any>,
        decryptOld: (cipherQb64: string) => Promise<Uint8Array>,
        signRot: (raw: Uint8Array) => Promise<Uint8Array>,
        opts: {
            recoveryFromIcp?: boolean;
            sn?: number;
            offCard?: boolean;
            // Override the rot's `n` commitment. Lets the caller
            // build a multi-card next, swap one card for a different
            // one entirely, or attach an explicit threshold without
            // forcing a follow-up signify-ts API change. When set,
            // `nextCardPubQb64` is ignored for the n[] computation
            // (it still feeds the per-AID encrypter so the wallet
            // can decrypt later via the new chip slot).
            nextNdigs?: string[];
            // Threshold for the new n[] commitment. Defaults to '1'.
            nsith?: string | string[];
            // Model B: re-key the sxlt encrypter to the new bran's
            // salter signer so normal signing stays bran-based and
            // tap-free, while n[] still commits the card next-pub
            // (wallet stays card-bound). The bran is recoverable
            // via the on-card escrow blob.
            aeidUnderNewBran?: boolean;
            // Prior event said to chain the rot to. Lets the caller rotate
            // AFTER an anchoring ixn (a profile's delegation seal) instead of
            // superseding it from the establishment event. Pair with opts.sn.
            priorDig?: string;
        } = {}
    ): Promise<{
        rot: Record<string, unknown>;
        sigs: string[];
        sxlt: string;
        keys: Record<string, any>;
    }> {
        // 1. Derive the new current signer from nbran.
        const newBranQb64 = MtrDex.Salt_128 + 'A' + nbran.substring(0, 21);
        const newSalter = new Salter({ qb64: newBranQb64, tier: this.tier });
        const newCreator = new SaltyCreator(
            newSalter.qb64,
            this.tier,
            this.stem
        );
        const newSigner = newCreator
            .create(undefined, 1, MtrDex.Ed25519_Seed, true, 0, 0, 0, false)
            .signers.pop();

        // offCard variant: also derive the next bran-side signer so the
        // rot's n[] commits a bran-derived digest instead of the next
        // card pub. After the rotation the controller's next-key
        // commitment is fully back on the phone.
        const newNsigner = opts.offCard
            ? newCreator
                  .create(
                      undefined,
                      1,
                      MtrDex.Ed25519_Seed,
                      true,
                      0,
                      1,
                      0,
                      false
                  )
                  .signers.pop()
            : undefined;

        // 2. Build the rot's n[] commitment.
        let ndigs: string[];
        const nsith: string | string[] = opts.nsith ?? '1';
        if (opts.nextNdigs && opts.nextNdigs.length > 0) {
            ndigs = opts.nextNdigs;
        } else if (opts.offCard) {
            ndigs = [
                new Diger(
                    { code: MtrDex.Blake3_256 },
                    newNsigner!.verfer.qb64b
                ).qb64,
            ];
        } else {
            const nextCardVerfer = new Verfer({ qb64: nextCardPubQb64 });
            ndigs = [
                new Diger(
                    { code: MtrDex.Blake3_256 },
                    nextCardVerfer.qb64b
                ).qb64,
            ];
        }

        // 3. Build the dual-key rot serder. The card's pub (the
        // previously-committed next) must appear in k as the revealed old
        // next, alongside the new bran-derived current. Weighted threshold
        // [new=1, old=0]: new current carries signing weight, old next is
        // revealed for verification only.
        const cardVerfer = new Verfer({ qb64: cardPubQb64 });
        const newKeys = [newSigner!.verfer.qb64, cardVerfer.qb64];
        // recoveryFromIcp overrides the prior dig with the controller's own
        // inception said (= controller.pre) so KERIA validates the rot's k
        // against the icp's original n, skipping any intermediate event an
        // attacker may have inserted. The disputed sn must still be greater
        // than the latest seen sn; the caller supplies it via opts.sn.
        const priorDig =
            opts.priorDig ??
            (opts.recoveryFromIcp
                ? this.pre
                : (this.serder.sad['d'] as string));
        const nextSn =
            opts.sn ?? new CesrNumber({}, this.serder.sad['s']).num + 1;
        const rot = rotate({
            pre: this.pre,
            keys: newKeys,
            dig: priorDig,
            sn: nextSn,
            isith: ['1', '0'],
            nsith,
            ndigs,
            wits: this.wits,
            toad: this.toad,
        });

        // 4. Two sigs: card at index 1 ondex 0 (revealed old next), new
        // bran at index 0 (new current).
        const cardSigRaw = await signRot(b(rot.raw));
        const cardSiger = new Siger({
            raw: cardSigRaw,
            code: IdrDex.Ed25519_Big_Sig,
            index: 1,
            ondex: 0,
        });
        const newSiger = newSigner!.sign(b(rot.raw), 0);
        const sigs = [newSiger.qb64, cardSiger.qb64];

        // 5. Encrypter for the new sxlt blobs.
        const newBranAeidSigner = newSalter.signer(
            MtrDex.Ed25519_Seed,
            true,
            '',
            this.tier
        );
        const encrypter =
            opts.offCard || opts.aeidUnderNewBran
                ? new Encrypter({}, b(newBranAeidSigner.verfer.qb64))
                : new Encrypter({}, b(nextCardPubQb64));

        // 6. New top-level sxlt: encrypted new bran.
        const sxlt = encrypter.encrypt(b(newBranQb64)).qb64;

        // 7. Per-AID re-encryption.
        const keys: Record<string, any> = {};
        for (const aid of aids) {
            const pre = aid['prefix'] as string;
            if ('salty' in aid) {
                const salty = aid['salty'];
                // The card decrypts the OLD sxlt and returns plaintext
                // bytes. The host wraps card.ecdh() + libsodium symmetric
                // open in this callback.
                const plaintext = await decryptOld(salty['sxlt'] as string);
                const newSxlt = encrypter.encrypt(plaintext).qb64;
                keys[pre] = { sxlt: newSxlt };
            } else if ('randy' in aid) {
                // Randy AIDs store each signing/next priv encrypted
                // independently. Decrypt every blob via the card and
                // re-encrypt under the new next-card pub.
                const randy = aid['randy'];
                const oldPrxs = (randy['prxs'] ?? []) as string[];
                const oldNxts = (randy['nxts'] ?? []) as string[];
                const newPrxs: string[] = [];
                const newNxts: string[] = [];
                for (const prx of oldPrxs) {
                    const plaintext = await decryptOld(prx);
                    newPrxs.push(encrypter.encrypt(plaintext).qb64);
                }
                for (const nxt of oldNxts) {
                    const plaintext = await decryptOld(nxt);
                    newNxts.push(encrypter.encrypt(plaintext).qb64);
                }
                keys[pre] = { prxs: newPrxs, nxts: newNxts };
            }
            // extern AIDs: nothing to re-encrypt; KERIA keeps the prefix
            // store and the extern_type via the ExternKeeper patch.
            // group AIDs: their material lives in member habs.
        }

        // 8. Commit the new state on this Controller.
        this.bran = newBranQb64;
        this.salter = newSalter;
        this.signer = newSigner;
        // Card path: the next is the card itself, so the local nsigner is
        // meaningless. offCard path: restore the bran-derived nsigner so
        // future standard rotate() calls can chain.
        this.nsigner = opts.offCard ? newNsigner : undefined;
        this.keys = newKeys;
        this.ndigs = ndigs;
        this.serder = rot;
        this.ridx += 1;

        return {
            rot: rot.sad,
            sigs,
            sxlt,
            keys,
        };
    }

    /**
     * Retrofit a recovery card onto an EXISTING wallet whose controller
     * AID was not provisioned with an external next-key.
     *
     * Runs the standard {@link rotate} to advance the controller bran and
     * re-encrypt every AID's sxlt, then rebuilds the rot serder so its `n`
     * array is the host-supplied digest array (the digest of
     * `card.slot0.pub_0`) instead of the bran-derived next.
     */
    rotateWithExternalNext(
        bran: string,
        aids: Array<any>,
        nextOverride: string[],
        opts: {
            // Explicit sn/prior for the rebuilt rot. The standard rotate
            // derives them from this.serder, which after connect is the
            // establishment event; if the KEL advanced past it with an
            // anchoring ixn (agent delegation seal) the derived rot lands
            // ON that ixn's sn and KERIA rejects it as a bad recovery
            // attempt. Same override pair rotateForRecovery already takes.
            sn?: number;
            priorDig?: string;
        } = {}
    ): Record<string, unknown> {
        if (!nextOverride || nextOverride.length === 0) {
            throw new Error('rotateWithExternalNext: nextOverride required');
        }
        // Re-derive the OLD next signer BEFORE calling rotate(): it
        // overwrites this.salter. The OLD next is the second key in the
        // dual-key rotation shape and signs at index 1 ondex 0.
        const oldCreator = new SaltyCreator(
            this.salter.qb64,
            this.tier,
            this.stem
        );
        const oldNextSigner = oldCreator
            .create(
                undefined,
                1,
                MtrDex.Ed25519_Seed,
                true,
                0,
                this.ridx + 1,
                0,
                false
            )
            .signers.pop();

        // Run the standard rotate so re-encryption side effects happen.
        const body: any = this.rotate(bran, aids);

        // Rebuild rot with the override ndigs but the SAME dual-key shape
        // and threshold the standard rotate emitted. sn/prior come from
        // opts when the caller knows the KEL's true head (see opts docs),
        // else fall back to what the standard rotate derived.
        const rebuiltSn =
            opts.sn ?? new CesrNumber({}, body.rot.s as string).num;
        const rebuilt = rotate({
            pre: this.pre,
            keys: this.keys,
            dig: opts.priorDig ?? body.rot.p,
            sn: rebuiltSn,
            isith: body.rot.kt,
            nsith: '1',
            ndigs: nextOverride,
        });

        const sigs = [
            oldNextSigner!.sign(b(rebuilt.raw), 1, false, 0).qb64,
            this.signer.sign(b(rebuilt.raw), 0).qb64,
        ];

        this.ndigs = nextOverride;
        this.serder = rebuilt;
        return { ...body, rot: rebuilt.sad, sigs };
    }

    /**
     * Commit an external next-key digest (a hardware recovery card's pub) as
     * the controller's new next with a MINIMAL single-key rotation that keeps
     * the SAME bran. The rotation-time twin of {@link setExternalNext}: it
     * reveals the pre-committed bran next-key as the new current (so the phone
     * keeps signing tap-free), sets n to the external digest, and leaves the
     * bran untouched. Because the bran (hence the per-AID sxlt aeid) doesn't
     * change there is nothing to re-encrypt: keys is empty and sxlt is the
     * current bran re-wrapped under the unchanged aeid.
     *
     * Unlike {@link rotateWithExternalNext} this does NOT run the passcode
     * rotation machinery (no new bran, no dual-key reveal, no per-AID
     * re-encryption), so it needs no aids or aid HabStates.
     *
     * opts.sn/priorDig chain the rot after the KEL's true head (a profile's
     * agent-delegation ixn), same as {@link rotateForRecovery}.
     */
    rotateExternalNext(
        externalNdigs: string[],
        opts: { sn?: number; priorDig?: string } = {}
    ): Record<string, unknown> {
        if (!externalNdigs || externalNdigs.length === 0) {
            throw new Error('rotateExternalNext: externalNdigs required');
        }

        // The pre-committed next is the bran signer at ridx+1. Revealing it as
        // the new current is a plain single-key rotation the phone can sign.
        const creator = new SaltyCreator(
            this.salter.qb64,
            this.tier,
            this.stem
        );
        const newCurrent = creator
            .create(
                undefined,
                1,
                MtrDex.Ed25519_Seed,
                true,
                0,
                this.ridx + 1,
                0,
                false
            )
            .signers.pop()!;
        const newKeys = [newCurrent.verfer.qb64];

        const priorDig = opts.priorDig ?? (this.serder.sad['d'] as string);
        const sn =
            opts.sn ??
            new CesrNumber({}, this.serder.sad['s'] as string).num + 1;
        const rot = rotate({
            pre: this.pre,
            keys: newKeys,
            dig: priorDig,
            sn,
            isith: '1',
            nsith: '1',
            ndigs: externalNdigs,
            wits: this.wits,
            toad: this.toad,
        });
        const sigs = [newCurrent.sign(b(rot.raw), 0).qb64];

        // Bran unchanged -> aeid unchanged -> sxlt is the same bran re-wrapped
        // and no per-AID salt needs re-keying.
        const aeidSigner = this.salter.signer(undefined, false);
        const encrypter = new Encrypter({}, b(aeidSigner.verfer.qb64));
        const sxlt = encrypter.encrypt(b(this.bran)).qb64;

        // Commit the new state locally. The next is the card, so the local
        // bran-derived nsigner is meaningless.
        this.signer = newCurrent;
        this.keys = newKeys;
        this.ndigs = externalNdigs;
        this.nsigner = undefined;
        this.serder = rot;
        this.ridx += 1;

        return { rot: rot.sad, sigs, sxlt, keys: {} };
    }

    /**
     * Rotate the controller from card-backed back to a fresh seed (bran) in
     * TWO clean single-key rotations, instead of the dual-key reveal
     * rotateForRecovery uses (only valid as a superseding recovery, which
     * mid-KEL leaves a 2-key controller the single-key Authenticater can't
     * drive). Prior state after a backup is k=[bran], n=[card]:
     *
     *   rot1: reveal k=[card] (matches the prior n=[card]), commit
     *         n=[digest(nb0)]. Signed by the card (the revealed next).
     *   rot2: reveal k=[nb0] (matches rot1.n), commit n=[digest(nb1)].
     *         Signed by nb0 (the new bran current, phone-held).
     *
     * End state: k=[nb0] single, next bran-derived -> phone controls,
     * seed-recoverable, and the next backup's rotateExternalNext chains
     * cleanly. Returns BOTH events; the caller PUTs rot1 then rot2. rot1's
     * PUT must carry card-signed auth headers (KERIA validates headers
     * against post-rot1 k[0]=card); rot2's headers are nb0-signed.
     */
    async rotateOffCardToSeed(
        nbran: string,
        cardCurPubQb64: string,
        aids: Array<any>,
        decryptOld: (cipherQb64: string) => Promise<Uint8Array>,
        signRot: (raw: Uint8Array) => Promise<Uint8Array>,
        opts: { sn?: number; priorDig?: string } = {}
    ): Promise<{
        rot1: Record<string, unknown>;
        sigs1: string[];
        sxlt1: string;
        keys1: Record<string, any>;
        rot2: Record<string, unknown>;
        sigs2: string[];
        sxlt2: string;
        keys2: Record<string, any>;
    }> {
        // New bran signers: nb0 = current after rot2, nb1 = its next.
        const newBranQb64 = MtrDex.Salt_128 + 'A' + nbran.substring(0, 21);
        const newSalter = new Salter({ qb64: newBranQb64, tier: this.tier });
        const newCreator = new SaltyCreator(
            newSalter.qb64,
            this.tier,
            this.stem
        );
        const nb0 = newCreator
            .create(undefined, 1, MtrDex.Ed25519_Seed, true, 0, 0, 0, false)
            .signers.pop()!;
        const nb1 = newCreator
            .create(undefined, 1, MtrDex.Ed25519_Seed, true, 0, 1, 0, false)
            .signers.pop()!;

        // rot1: reveal the card key as the sole new current. Its digest is
        // already the prior n (from the backup), so a plain single-key rot.
        const cardVerfer = new Verfer({ qb64: cardCurPubQb64 });
        const priorDig1 = opts.priorDig ?? (this.serder.sad['d'] as string);
        const sn1 =
            opts.sn ??
            new CesrNumber({}, this.serder.sad['s'] as string).num + 1;
        const nb0Digest = new Diger(
            { code: MtrDex.Blake3_256 },
            nb0.verfer.qb64b
        ).qb64;
        const rot1 = rotate({
            pre: this.pre,
            keys: [cardVerfer.qb64],
            dig: priorDig1,
            sn: sn1,
            isith: '1',
            nsith: '1',
            ndigs: [nb0Digest],
            wits: this.wits,
            toad: this.toad,
        });
        const card1Raw = await signRot(b(rot1.raw));
        const sigs1 = [
            new Siger({
                raw: card1Raw,
                code: IdrDex.Ed25519_Sig,
                index: 0,
            }).qb64,
        ];
        // rot1 doesn't touch the bran; keep the current sxlt (old bran under
        // old aeid) so KERIA's manager stays consistent through the transient
        // card-current step. No per-AID re-key here.
        const oldAeidSigner = this.salter.signer(undefined, false);
        const sxlt1 = new Encrypter({}, b(oldAeidSigner.verfer.qb64))
            .encrypt(b(this.bran))
            .qb64;

        // rot2: reveal nb0 (matches rot1.n) as the sole new current, commit
        // nb1 as next. nb0 is phone-held so the phone signs it.
        const priorDig2 = rot1.sad['d'] as string;
        const sn2 = sn1 + 1;
        const nb1Digest = new Diger(
            { code: MtrDex.Blake3_256 },
            nb1.verfer.qb64b
        ).qb64;
        const rot2 = rotate({
            pre: this.pre,
            keys: [nb0.verfer.qb64],
            dig: priorDig2,
            sn: sn2,
            isith: '1',
            nsith: '1',
            ndigs: [nb1Digest],
            wits: this.wits,
            toad: this.toad,
        });
        const sigs2 = [nb0.sign(b(rot2.raw), 0).qb64];

        // rot2 switches the bran to nbran: re-key the aeid like
        // rotateForRecovery does (proven by the onboarding-recovery path).
        const newBranAeidSigner = newSalter.signer(
            MtrDex.Ed25519_Seed,
            true,
            '',
            this.tier
        );
        const encrypter = new Encrypter({}, b(newBranAeidSigner.verfer.qb64));
        const sxlt2 = encrypter.encrypt(b(newBranQb64)).qb64;
        const keys2: Record<string, any> = {};
        for (const aid of aids) {
            const pre = aid['prefix'] as string;
            if ('salty' in aid) {
                const plaintext = await decryptOld(
                    aid['salty']['sxlt'] as string
                );
                keys2[pre] = { sxlt: encrypter.encrypt(plaintext).qb64 };
            } else if ('randy' in aid) {
                const randy = aid['randy'];
                const oldPrxs = (randy['prxs'] ?? []) as string[];
                const oldNxts = (randy['nxts'] ?? []) as string[];
                const newPrxs: string[] = [];
                const newNxts: string[] = [];
                for (const prx of oldPrxs) {
                    newPrxs.push(
                        encrypter.encrypt(await decryptOld(prx)).qb64
                    );
                }
                for (const nxt of oldNxts) {
                    newNxts.push(
                        encrypter.encrypt(await decryptOld(nxt)).qb64
                    );
                }
                keys2[pre] = { prxs: newPrxs, nxts: newNxts };
            }
        }

        // Commit local state to rot2 (the final, phone-controlled state).
        this.bran = newBranQb64;
        this.salter = newSalter;
        this.signer = nb0;
        this.nsigner = nb1;
        this.keys = [nb0.verfer.qb64];
        this.ndigs = [nb1Digest];
        this.serder = rot2;
        this.ridx += 1;

        return {
            rot1: rot1.sad,
            sigs1,
            sxlt1,
            keys1: {},
            rot2: rot2.sad,
            sigs2,
            sxlt2,
            keys2,
        };
    }

    /**
     * Replace the inception event's next-key commitment with externally
     * provided digests and rebuild this.serder. Used by hosts that want the
     * controller AID to be rotatable via an external signer (e.g. a hardware
     * recovery card whose key was not derived from the controller bran).
     *
     * Must be called before .boot() and only when ridx == 0 (no rotations
     * yet). For rotations the next commit is set inside .rotate() so this
     * setter has no effect there.
     */
    setExternalNext(
        ndigs: string[],
        opts: { wits?: string[]; toad?: number } = {}
    ) {
        if (this.ridx !== 0) {
            throw new Error(
                'setExternalNext: controller has already rotated, ' +
                    'override only valid at inception'
            );
        }
        if (!ndigs || ndigs.length === 0) {
            throw new Error('setExternalNext: ndigs required');
        }
        this.ndigs = ndigs;
        if (opts.wits !== undefined) {
            this.wits = opts.wits;
        }
        if (opts.toad !== undefined) {
            this.toad = opts.toad;
        } else if (opts.wits !== undefined) {
            this.toad =
                opts.wits.length === 0
                    ? 0
                    : Math.max(1, Math.ceil((opts.wits.length * 2) / 3));
        }
        this.serder = incept({
            keys: this.keys,
            isith: '1',
            nsith: '1',
            ndigs: this.ndigs,
            code: MtrDex.Blake3_256,
            toad: this.toad,
            wits: this.wits,
        });
    }
}
