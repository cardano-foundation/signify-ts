import { strict as assert } from 'assert';
import { SignifyClient } from '../../src/keri/app/clienting';
import { Tier } from '../../src/keri/core/salter';
import libsodium from 'libsodium-wrappers-sumo';
import {
    d,
    Ident,
    Ilks,
    interact,
    Saider,
    Serder,
    serializeACDCAttachment,
    serializeIssExnAttachment,
    Serials,
    versify,
} from '../../src/index';
import { createMockFetch, mockCredential } from './test-utils';

const fetchMock = createMockFetch();

const url = 'http://127.0.0.1:3901';
const boot_url = 'http://127.0.0.1:3903';

describe('Credentialing', () => {
    it('Credentials', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';

        const client = new SignifyClient(url, bran, Tier.low, boot_url);

        await client.boot();
        await client.connect();

        const credentials = client.credentials();

        const kargs = {
            filter: {
                '-i': { $eq: 'EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX' },
            },
            sort: [{ '-s': 1 }],
            skip: 5,
            limit: 25,
        };
        await credentials.list(kargs);
        let lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(lastCall[0].url, url + '/credentials/query');
        assert.equal(lastCall[0].method, 'POST');
        assert.deepEqual(await lastCall[0].text(), JSON.stringify(kargs));

        await credentials.get(
            'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
            true
        );
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            url + '/credentials/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'
        );
        assert.equal(lastCall[0].method, 'GET');

        const registry = 'EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX';
        const schema = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
        const isuee = 'EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p';
        await credentials.issue('aid1', {
            ri: registry,
            s: schema,
            a: { i: isuee, LEI: '1234' },
        });
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        let lastBody = JSON.parse(await lastCall[0].text());
        assert.equal(lastCall[0].url, url + '/identifiers/aid1/credentials');
        assert.equal(lastCall[0].method, 'POST');
        assert.equal(lastBody.acdc.ri, registry);
        assert.equal(lastBody.acdc.s, schema);
        assert.equal(lastBody.acdc.a.i, isuee);
        assert.equal(lastBody.acdc.a.LEI, '1234');
        assert.equal(lastBody.iss.s, '0');
        assert.equal(lastBody.iss.t, 'iss');
        assert.equal(lastBody.iss.ri, registry);
        assert.equal(lastBody.iss.i, lastBody.acdc.d);
        assert.equal(lastBody.ixn.t, 'ixn');
        assert.equal(lastBody.ixn.i, lastBody.acdc.i);
        assert.equal(lastBody.ixn.p, lastBody.acdc.i);
        assert.equal(lastBody.sigs[0].substring(0, 2), 'AA');
        assert.equal(lastBody.sigs[0].length, 88);

        const credential = lastBody.acdc.i;
        await credentials.revoke('aid1', credential);
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        lastBody = JSON.parse(await lastCall[0].text());
        assert.equal(
            lastCall[0].url,
            url + '/identifiers/aid1/credentials/' + credential
        );
        assert.equal(lastCall[0].method, 'DELETE');
        assert.equal(lastBody.rev.s, '1');
        assert.equal(lastBody.rev.t, 'rev');
        assert.equal(
            lastBody.rev.ri,
            'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df'
        );
        assert.equal(
            lastBody.rev.i,
            'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK'
        );
        assert.equal(lastBody.ixn.t, 'ixn');
        assert.equal(
            lastBody.ixn.i,
            'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK'
        );
        assert.equal(
            lastBody.ixn.p,
            'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK'
        );
        assert.equal(lastBody.sigs[0].substring(0, 2), 'AA');
        assert.equal(lastBody.sigs[0].length, 88);

        await credentials.state(mockCredential.sad.ri, mockCredential.sad.d);
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            url +
                '/registries/EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df/EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo'
        );
        assert.equal(lastCall[0].method, 'GET');
        assert.equal(lastCall[0].body, null);

        await credentials.delete(mockCredential.sad.d);
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            url + '/credentials/EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo'
        );
        assert.equal(lastCall[0].method, 'DELETE');
        assert.equal(lastCall[0].body, null);
    });
});

describe('Ipex', () => {
    it('IPEX - grant-admit flow initiated by discloser', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';
        const client = new SignifyClient(url, bran, Tier.low, boot_url);

        await client.boot();
        await client.connect();

        const ipex = client.ipex();

        const holder = 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k';
        const [, acdc] = Saider.saidify(mockCredential.sad);

        // Create iss
        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0);
        const _iss = {
            v: vs,
            t: Ilks.iss,
            d: '',
            i: mockCredential.sad.d,
            s: '0',
            ri: mockCredential.sad.ri,
            dt: mockCredential.sad.a.dt,
        };

        const [, iss] = Saider.saidify(_iss);
        const iserder = new Serder(iss);
        const anc = interact({
            pre: mockCredential.sad.i,
            sn: 1,
            data: [{}],
            dig: mockCredential.sad.d,
            version: undefined,
            kind: undefined,
        });

        const [grant, gsigs, end] = await ipex.grant({
            senderName: 'multisig',
            recipient: holder,
            message: '',
            acdc: new Serder(acdc),
            iss: iserder,
            anc,
            datetime: mockCredential.sad.a.dt,
        });

        assert.deepStrictEqual(grant.ked, {
            v: 'KERI10JSON0004b2_',
            t: 'exn',
            d: 'EFYfsW_8h3Tg8p8k4PyPpgTaz81K4g0oZoQhElcp9svD',
            i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
            p: '',
            dt: '2023-08-23T15:16:07.553000+00:00',
            r: '/ipex/grant',
            rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
            q: {},
            a: { m: '' },
            e: {
                acdc: {
                    v: 'ACDC10JSON000197_',
                    d: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                    i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                    ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                    s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                    a: {
                        d: 'EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P',
                        i: 'EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby',
                        dt: '2023-08-23T15:16:07.553000+00:00',
                        LEI: '5493001KJTIIGC8Y1R17',
                    },
                },
                iss: {
                    v: 'KERI10JSON0000ed_',
                    t: 'iss',
                    d: 'ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW',
                    i: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                    s: '0',
                    ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                    dt: '2023-08-23T15:16:07.553000+00:00',
                },
                anc: {
                    v: 'KERI10JSON0000cd_',
                    t: 'ixn',
                    d: 'ECVCyxNpB4PJkpLbWqI02WXs1wf7VUxPNY2W28SN2qqm',
                    i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                    s: '1',
                    p: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                    a: [{}],
                },
                d: 'EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-',
            },
        });

        assert.deepStrictEqual(gsigs, [
            'AACeaOv4L2DshEfm0Bz7A7M7N25-P3GW7dqgC8Gm_7BCesEdPXgI7nl5QbfVc-iXvJsErD-FNTqDFHLDRnbinRED',
        ]);
        assert.equal(
            end,
            '-LAg4AACA-e-acdc-IABEMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo0AAAAAAAAAAAAAAAAAAAAAAAENf3IEYwYtFmlq5Zz' +
                'oI-zFzeR7E3ZNRN2YH_0KAFbdJW-LAW5AACAA-e-iss-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAAAECVCyxNpB4PJkpLbWqI02WXs1wf7VU' +
                'xPNY2W28SN2qqm-LAa5AACAA-e-anc-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZo' +
                'Vp8j2uxTTPkItO7ED'
        );

        const [ng, ngsigs, ngend] = await ipex.grant({
            senderName: 'multisig',
            recipient: holder,
            message: '',
            acdc: new Serder(acdc),
            acdcAttachment: d(serializeACDCAttachment(iserder)),
            iss: iserder,
            issAttachment: d(serializeIssExnAttachment(anc)),
            anc,
            ancAttachment:
                '-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZoVp8j2uxTTPkItO7ED',
            datetime: mockCredential.sad.a.dt,
        });

        assert.deepStrictEqual(ng.ked, grant.ked);
        assert.deepStrictEqual(ngsigs, gsigs);
        assert.deepStrictEqual(ngend, ngend);

        await ipex.submitGrant('multisig', ng, ngsigs, ngend, [holder]);
        let lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            'http://127.0.0.1:3901/identifiers/multisig/ipex/grant'
        );

        const [admit, asigs, aend] = await ipex.admit({
            senderName: 'holder',
            message: '',
            grantSaid: grant.ked.d,
            recipient: holder,
            datetime: mockCredential.sad.a.dt,
        });

        assert.deepStrictEqual(admit.ked, {
            v: 'KERI10JSON000145_',
            t: 'exn',
            d: 'EHynwUZNfo3GCW2AkAyu7B8XGc_Uw4f8YuXU4xtf7k5t',
            i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
            p: 'EFYfsW_8h3Tg8p8k4PyPpgTaz81K4g0oZoQhElcp9svD',
            dt: '2023-08-23T15:16:07.553000+00:00',
            r: '/ipex/admit',
            rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
            q: {},
            a: { m: '' },
            e: {},
        });

        assert.deepStrictEqual(asigs, [
            'AADvfvY47Q97U2OBiDHOY4ZXSFQZp077vBd8PVQZqDNX9CV5NtneWerbzdgQ7bvdsKUl75x0y5iXAsRRzLrVrT0B',
        ]);

        await ipex.submitAdmit('multisig', admit, asigs, aend, [holder]);
        lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            'http://127.0.0.1:3901/identifiers/multisig/ipex/admit'
        );

        assert.equal(aend, '');
    });

    it('IPEX - apply-admit flow initiated by disclosee', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';
        const client = new SignifyClient(url, bran, Tier.low, boot_url);

            await client.boot();
            await client.connect();

            const ipex = client.ipex();

            const holder = 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k';
            const [, acdc] = Saider.saidify(mockCredential.sad);

            // Create iss
            const vs = versify(Ident.KERI, undefined, Serials.JSON, 0);
            const _iss = {
                v: vs,
                t: Ilks.iss,
                d: '',
                i: mockCredential.sad.d,
                s: '0',
                ri: mockCredential.sad.ri,
                dt: mockCredential.sad.a.dt,
            };

            const [, iss] = Saider.saidify(_iss);
            const iserder = new Serder(iss);
            const anc = interact({
                pre: mockCredential.sad.i,
                sn: 1,
                data: [{}],
                dig: mockCredential.sad.d,
                version: undefined,
                kind: undefined,
            });

            const [apply, applySigs, applyEnd] = await ipex.apply({
                senderName: 'multisig',
                recipient: holder,
                message: 'Applying',
                schemaSaid: mockCredential.sad.s,
                attributes: { LEI: mockCredential.sad.a.LEI },
                datetime: mockCredential.sad.a.dt,
            });

            assert.deepStrictEqual(apply.ked, {
                v: 'KERI10JSON000177_',
                t: 'exn',
                d: 'EDFeDvVMgLiDm3zV_A9fDk7gY4tEDFfQupScvNgABBXw',
                i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
                p: '',
                dt: '2023-08-23T15:16:07.553000+00:00',
                r: '/ipex/apply',
                rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
                q: {},
                a: {
                    m: 'Applying',
                    s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                    a: { LEI: '5493001KJTIIGC8Y1R17' },
                },
                e: {},
            });

        assert.deepStrictEqual(applySigs, [
            'AABdbLeRZ6RlWhiyCobCcg8FXhVCPZ3A0XlOKM5a6s1ZhI88cNlcHVzQGTGV4bB-y3ySeMGczzKQVCyf4lg1ZJQA',
        ]);

            assert.equal(applyEnd, '');

            await ipex.submitApply('multisig', apply, applySigs, [holder]);
            let lastCall =
                fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
            assert(lastCall[0] instanceof Request);
            assert.equal(
                lastCall[0].url,
                'http://127.0.0.1:3901/identifiers/multisig/ipex/apply'
            );

            const [offer, offerSigs, offerEnd] = await ipex.offer({
                senderName: 'multisig',
                recipient: holder,
                message: 'How about this',
                acdc: new Serder(acdc),
                datetime: mockCredential.sad.a.dt,
                applySaid: apply.ked.d,
            });

            assert.deepStrictEqual(offer.ked, {
                v: 'KERI10JSON000324_',
                t: 'exn',
                d: 'EDocl1gyKIfm7Cj3gjoUkwLjl6KrB6l2HrkPLEMMBlig',
                i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
                p: 'EDFeDvVMgLiDm3zV_A9fDk7gY4tEDFfQupScvNgABBXw',
                dt: '2023-08-23T15:16:07.553000+00:00',
                r: '/ipex/offer',
                rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
                q: {},
                a: {
                    m: 'How about this',
                },
                e: {
                    acdc: {
                        v: 'ACDC10JSON000197_',
                        d: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                        i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                        ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                        s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                        a: {
                            d: 'EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P',
                            i: 'EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby',
                            dt: '2023-08-23T15:16:07.553000+00:00',
                            LEI: '5493001KJTIIGC8Y1R17',
                        },
                    },
                    d: 'EK72JZyOyz81Jvt--iebptfhIWiw2ZdQg7ondKd-EyJF',
                },
            });

        assert.deepStrictEqual(offerSigs, [
            'AABPcf_WNQISpvPj5CI9QekftQenP_R_St8P2rpWwPJXY4NCCQsHUwAZomPN28ujDDGxYU3x1a1JbLIUyZylhE0I',
        ]);
        assert.equal(offerEnd, '');

            await ipex.submitOffer('multisig', offer, offerSigs, offerEnd, [
                holder,
            ]);
            lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
            assert(lastCall[0] instanceof Request);
            assert.equal(
                lastCall[0].url,
                'http://127.0.0.1:3901/identifiers/multisig/ipex/offer'
            );

            const [agree, agreeSigs, agreeEnd] = await ipex.agree({
                senderName: 'multisig',
                recipient: holder,
                message: 'OK!',
                datetime: mockCredential.sad.a.dt,
                offerSaid: offer.ked.d,
            });

            assert.deepStrictEqual(agree.ked, {
                v: 'KERI10JSON000148_',
                t: 'exn',
                d: 'EFBg4k0ICOSB_kSYtVQ6HymynENxShlJxB6e4kLCrRTd',
                i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
                p: 'EDocl1gyKIfm7Cj3gjoUkwLjl6KrB6l2HrkPLEMMBlig',
                dt: '2023-08-23T15:16:07.553000+00:00',
                r: '/ipex/agree',
                rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
                q: {},
                a: {
                    m: 'OK!',
                },
                e: {},
            });

        assert.deepStrictEqual(agreeSigs, [
            'AADy0GdBWaL_9fU8zD-UFC5c2tV8ejfCHncK_sBltryo2VfkSHkyf8SroAwxmXJgrUVJRvoC68dLa_PzuaYf9pYG',
        ]);
        assert.equal(agreeEnd, '');

            await ipex.submitAgree('multisig', agree, agreeSigs, [holder]);
            lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
            assert(lastCall[0] instanceof Request);
            assert.equal(
                lastCall[0].url,
                'http://127.0.0.1:3901/identifiers/multisig/ipex/agree'
            );

            const [grant, gsigs, end] = await ipex.grant({
                senderName: 'multisig',
                recipient: holder,
                message: '',
                acdc: new Serder(acdc),
                iss: iserder,
                anc,
                datetime: mockCredential.sad.a.dt,
                agreeSaid: agree.ked.d,
            });

            assert.deepStrictEqual(grant.ked, {
                v: 'KERI10JSON0004de_',
                t: 'exn',
                d: 'ELm3X5SkBDpwziA8h-NvHdHoxYv0H5866t6xPleWYjqo',
                i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
                p: 'EFBg4k0ICOSB_kSYtVQ6HymynENxShlJxB6e4kLCrRTd',
                dt: '2023-08-23T15:16:07.553000+00:00',
                r: '/ipex/grant',
                rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
                q: {},
                a: { m: '' },
                e: {
                    acdc: {
                        v: 'ACDC10JSON000197_',
                        d: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                        i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                        ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                        s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                        a: {
                            d: 'EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P',
                            i: 'EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby',
                            dt: '2023-08-23T15:16:07.553000+00:00',
                            LEI: '5493001KJTIIGC8Y1R17',
                        },
                    },
                    iss: {
                        v: 'KERI10JSON0000ed_',
                        t: 'iss',
                        d: 'ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW',
                        i: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                        s: '0',
                        ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                        dt: '2023-08-23T15:16:07.553000+00:00',
                    },
                    anc: {
                        v: 'KERI10JSON0000cd_',
                        t: 'ixn',
                        d: 'ECVCyxNpB4PJkpLbWqI02WXs1wf7VUxPNY2W28SN2qqm',
                        i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                        s: '1',
                        p: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                        a: [{}],
                    },
                    d: 'EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-',
                },
            });

            assert.equal(gsigs.length, 1);
            assert.equal(gsigs[0].substring(0, 2), 'AA');
            assert.equal(gsigs[0].length, 88);
            assert.equal(
                end,
                '-LAg4AACA-e-acdc-IABEMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo0AAAAAAAAAAAAAAAAAAAAAAAENf3IEYwYtFmlq5Zz' +
                    'oI-zFzeR7E3ZNRN2YH_0KAFbdJW-LAW5AACAA-e-iss-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAAAECVCyxNpB4PJkpLbWqI02WXs1wf7VU' +
                    'xPNY2W28SN2qqm-LAa5AACAA-e-anc-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZo' +
                    'Vp8j2uxTTPkItO7ED'
            );

            const [ng, ngsigs, ngend] = await ipex.grant({
                senderName: 'multisig',
                recipient: holder,
                message: '',
                acdc: new Serder(acdc),
                acdcAttachment: d(serializeACDCAttachment(iserder)),
                iss: iserder,
                issAttachment: d(serializeIssExnAttachment(anc)),
                anc,
                ancAttachment:
                    '-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZoVp8j2uxTTPkItO7ED',
                datetime: mockCredential.sad.a.dt,
                agreeSaid: agree.ked.d,
            });

            assert.deepStrictEqual(ng.ked, grant.ked);
            assert.deepStrictEqual(ngsigs, gsigs);
            assert.deepStrictEqual(ngend, ngend);

            await ipex.submitGrant('multisig', ng, ngsigs, ngend, [holder]);
            lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
            assert(lastCall[0] instanceof Request);
            assert.equal(
                lastCall[0].url,
                'http://127.0.0.1:3901/identifiers/multisig/ipex/grant'
            );

            const [admit, asigs, aend] = await ipex.admit({
                senderName: 'holder',
                message: '',
                recipient: holder,
                grantSaid: grant.ked.d,
                datetime: mockCredential.sad.a.dt,
            });

            assert.deepStrictEqual(admit.ked, {
                v: 'KERI10JSON000145_',
                t: 'exn',
                d: 'EPWJ60ww3O5HxhdB2QGSXIV9W2mXHJ0hHjJU_nEDYei6',
                i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
                p: 'ELm3X5SkBDpwziA8h-NvHdHoxYv0H5866t6xPleWYjqo',
                dt: '2023-08-23T15:16:07.553000+00:00',
                r: '/ipex/admit',
                rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
                q: {},
                a: { m: '' },
                e: {},
            });

        assert.deepStrictEqual(asigs, [
            'AAA1kd_dmMUnS_NxB374EvglDitBScf8xil-sBg_5p1OHW9NEPKjGqKLaPNKv4FV0DxiDYinK182FXQQNeDAD4AI',
        ]);

            await ipex.submitAdmit('multisig', admit, asigs, aend, [holder]);
            lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
            assert(lastCall[0] instanceof Request);
            assert.equal(
                lastCall[0].url,
                'http://127.0.0.1:3901/identifiers/multisig/ipex/admit'
            );

            assert.equal(aend, '');
    });

    it('IPEX - discloser can create an offer without apply', async () => {
        await libsodium.ready;
        const bran = '0123456789abcdefghijk';
        const client = new SignifyClient(url, bran, Tier.low, boot_url);

        await client.boot();
        await client.connect();

        const ipex = client.ipex();

        const holder = 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k';
        const [, acdc] = Saider.saidify(mockCredential.sad);

        const [offer, offerSigs, offerEnd] = await ipex.offer({
            senderName: 'multisig',
            recipient: holder,
            message: 'Offering this',
            acdc: new Serder(acdc),
            datetime: mockCredential.sad.a.dt,
        });

        assert.deepStrictEqual(offer.ked, {
            v: 'KERI10JSON0002f7_',
            t: 'exn',
            d: 'EEBczFRrhu2JfGkG4_T4Md69mwoekXKb0i3LECwHzdYe',
            i: 'ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK',
            p: '',
            dt: '2023-08-23T15:16:07.553000+00:00',
            r: '/ipex/offer',
            rp: 'ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k',
            q: {},
            a: {
                m: 'Offering this',
            },
            e: {
                acdc: {
                    v: 'ACDC10JSON000197_',
                    d: 'EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo',
                    i: 'EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1',
                    ri: 'EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df',
                    s: 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao',
                    a: {
                        d: 'EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P',
                        i: 'EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby',
                        dt: '2023-08-23T15:16:07.553000+00:00',
                        LEI: '5493001KJTIIGC8Y1R17',
                    },
                },
                d: 'EK72JZyOyz81Jvt--iebptfhIWiw2ZdQg7ondKd-EyJF',
            },
        });

        assert.deepStrictEqual(offerSigs, [
            'AACUanMkgK-5YL1M7FEJdx20swK2x1f0MNSeQmE23Y9zGFSb-tlYASC_lUfCfPyz1lg_ErYJR7fw9xx5ig4iWrcC',
        ]);
        assert.equal(offerEnd, '');

        await ipex.submitOffer('multisig', offer, offerSigs, offerEnd, [
            holder,
        ]);
        const lastCall = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]!;
        assert(lastCall[0] instanceof Request);
        assert.equal(
            lastCall[0].url,
            'http://127.0.0.1:3901/identifiers/multisig/ipex/offer'
        );
    });
});
