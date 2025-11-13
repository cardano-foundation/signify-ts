import { assert, describe, it } from 'vitest';
import {
    Ilks,
    Protocols,
    Saider,
    SerderKERI,
    Serials,
    d,
    versify,
} from '../../src/index.ts';
import {
    serializeACDCAttachment,
    serializeIssExnAttachment,
} from '../../src/keri/core/utils.ts';

describe(serializeIssExnAttachment.name, () => {
    it('serializes iss data', () => {
        const [, data] = Saider.saidify({
            d: '',
            v: versify(Protocols.KERI, undefined, Serials.JSON, 0),
            t: Ilks.ixn,
            i: 'EIzPbk8zX7x8bXZ0KjXy7b4f4ZQF6Z5aT7c2yXhXvK1I',
            s: '3',
            p: 'EAbF5d2Q8vY3qF9hF6wY8rZ2qC3eL4nB9tK6yW7xN5P',
            a: [],
        });

        const result = serializeIssExnAttachment(new SerderKERI(data));

        assert.equal(
            d(result),
            '-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAAAELY2iQyTI3PJPF3mTw3zBkx136gTGsPHp1gw3R-9hITV'
        );
    });
});

describe(serializeACDCAttachment.name, () => {
    it('serializes acdc data', () => {
        const [, data] = Saider.saidify({
            i: 'EP-hA0w9X5FDonCDxQv32OTCAvcxkZxgDLOnDb3Jcn3a',
            d: '',
            v: versify(Protocols.ACDC, undefined, Serials.JSON, 0),
            a: {
                LEI: '123',
            },
            t: Ilks.iss,
            s: '2',
            ri: 'EReg123nVjV4q5yE1mT9wK2sR8nF6pB3aC0zJ7hM1tG5',
            dt: '2025-11-13T09:00:00.000000+00:00',
        });

        const result = serializeACDCAttachment(new SerderKERI(data));

        assert.equal(
            d(result),
            '-IABEP-hA0w9X5FDonCDxQv32OTCAvcxkZxgDLOnDb3Jcn3a0AAAAAAAAAAAAAAAAAAAAAAAEGwa907QzmzTRx6cH_zl_64l6G3l29AQEAK-7UuO3aDt'
        );
    });
});
