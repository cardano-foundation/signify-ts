import {
    deversify,
    Protocols,
    Serials,
    versify,
    Version,
    Vrsn_1_0,
} from './core.ts';
import { Diger } from './diger.ts';
import {
    DelegateInceptEventSAD,
    InceptEventSAD,
    InteractEventSAD,
    ReplyEventSAD,
    RotateEventSAD,
} from './eventing.ts';
import { MtrDex } from './matter.ts';
import { CesrNumber } from './number.ts';
import { Verfer } from './verfer.ts';

export type SerderSADType = Record<string, unknown> & {
    s?: string | number;
    d: string;
    i?: string;
};

export class Serder {
    private _kind: Serials;
    private _raw: string = '';
    protected _sad: SerderSADType;
    private _proto: Protocols = Protocols.KERI;
    private _size: number = 0;
    private _version: Version = Vrsn_1_0;
    private readonly _code: string;

    /**
     * Creates a new Serder object from a self-addressing data dictionary.
     * @param sad self-addressing data dictionary.
     * @param kind serialization type to produce
     * @param code derivation code for the prefix
     */
    constructor(
        sad: SerderSADType,
        kind: Serials = Serials.JSON,
        code: string = MtrDex.Blake3_256
    ) {
        const [raw, proto, eKind, eSad, version] = this._exhale(sad, kind);
        this._raw = raw;
        this._sad = eSad;
        this._proto = proto;
        this._version = version;
        this._code = code;
        this._kind = eKind;
        this._size = raw.length;
    }

    get sad(): SerderSADType {
        return this._sad;
    }

    get pre() {
        return this._sad['i'];
    }

    get code(): string {
        return this._code;
    }

    get raw(): string {
        return this._raw;
    }

    get said() {
        return this._sad['d'];
    }

    get sner(): CesrNumber {
        return new CesrNumber({}, this.sad['s']);
    }

    get sn(): number {
        return this.sner.num;
    }

    get kind(): Serials {
        return this._kind;
    }

    /**
     * Serializes a self-addressing data dictionary from the dictionary passed in
     * using the specified serialization type.
     * @param sad self-addressing data dictionary.
     * @param kind serialization type to produce
     * @private
     */
    private _exhale(
        sad: SerderSADType,
        kind: Serials
    ): [string, Protocols, Serials, SerderSADType, Version] {
        return sizeify(sad, kind);
    }

    get proto(): Protocols {
        return this._proto;
    }

    get size(): number {
        return this._size;
    }

    get version(): Version {
        return this._version;
    }
    get verfers(): Verfer[] {
        let keys: string[] = [];
        if ('k' in this._sad) {
            // establishment event
            if (
                Array.isArray(this._sad['k']) &&
                this._sad['k'].map((item) => typeof item === 'string')
            ) {
                keys = this._sad['k'];
            }
        } else {
            // non-establishment event
            keys = [];
        }
        // create a new Verfer for each key
        const verfers = [];
        for (const key of keys) {
            verfers.push(new Verfer({ qb64: key }));
        }
        return verfers;
    }

    get digers(): Diger[] {
        let keys: string[] = [];
        if ('n' in this._sad) {
            if (
                Array.isArray(this._sad['n']) &&
                this._sad['n'].map((item) => typeof item === 'string')
            ) {
                // establishment event
                keys = this._sad['n'];
            }
        } else {
            // non-establishment event
            keys = [];
        }
        // create a new Verfer for each key
        const digers = [];
        for (const key of keys) {
            digers.push(new Diger({ qb64: key }));
        }
        return digers;
    }

    pretty() {
        return JSON.stringify(this._sad, undefined, 2);
    }
}

export function dumps(sad: object, kind: Serials.JSON): string {
    if (kind == Serials.JSON) {
        return JSON.stringify(sad);
    } else {
        throw new Error('unsupported event encoding');
    }
}

export function sizeify<T extends object = Record<string, unknown>>(
    ked: T,
    kind?: Serials
): [string, Protocols, Serials, T, Version] {
    if (!('v' in ked)) {
        throw new Error('Missing or empty version string');
    }

    if (typeof ked['v'] !== 'string') {
        throw new Error('Invalid version string');
    }

    const [proto, knd, version] = deversify(ked['v']);
    if (version != Vrsn_1_0) {
        throw new Error(`unsupported version ${version.toString()}`);
    }

    if (kind == undefined) {
        kind = knd;
    }

    let raw = dumps(ked, kind);
    const size = new TextEncoder().encode(raw).length;

    ked['v'] = versify(proto, version, kind, size);

    raw = dumps(ked, kind);

    return [raw, proto, kind, ked, version];
}

type KERISAD =
    | RotateEventSAD
    | InceptEventSAD
    | DelegateInceptEventSAD
    | InteractEventSAD
    | ReplyEventSAD;

export class SerderKERI<T extends KERISAD = KERISAD> extends Serder {
    protected override _sad: T;

    constructor(
        sad: T,
        kind: Serials = Serials.JSON,
        code: string = MtrDex.Blake3_256
    ) {
        super(sad, kind, code);
        this._sad = sad;
    }

    get sad(): T {
        return this._sad;
    }
}
