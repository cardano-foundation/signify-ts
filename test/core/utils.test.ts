import { assert, describe, it } from 'vitest';
import {
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
        });

        const result = serializeIssExnAttachment(new SerderKERI(data));

        assert.equal(
            d(result),
            '-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAAAEKZPmzJqhx76bcC2ftPQgeRirmOd8ZBOtGVqHJrSm7F1'
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
        });

        const result = serializeACDCAttachment(new SerderKERI(data));

        assert.equal(
            d(result),
            '-IABEP-hA0w9X5FDonCDxQv32OTCAvcxkZxgDLOnDb3Jcn3a0AAAAAAAAAAAAAAAAAAAAAAAEHGU7u7cSMjMcJ1UyN8r-MnoZ3cDw4sMQNYxRLjqGVJI'
        );
    });
});
