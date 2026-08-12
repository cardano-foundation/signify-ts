import { strict as assert } from 'assert';
import { randomUUID } from 'crypto';
import { b, CredentialData, Serder, SignifyClient } from 'signify-ts';
import { resolveEnvironment } from './utils/resolve-env';
import {
    assertNotifications,
    assertOperations,
    createAid,
    getOrCreateClients,
    getOrCreateContact,
    markAndRemoveNotification,
    resolveOobi,
    waitForNotifications,
    waitOperation,
} from './utils/test-util';
import { step } from './utils/test-step';

const { vleiServerUrl } = resolveEnvironment();

const QVI_SCHEMA_SAID = 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao';
const QVI_SCHEMA_URL = `${vleiServerUrl}/oobi/${QVI_SCHEMA_SAID}`;

interface Aid {
    name: string;
    prefix: string;
    oobi: string;
}

function createTimestamp() {
    return new Date().toISOString().replace('Z', '000+00:00');
}

// waitForNotifications returns on the first match, so a duplicate landing just after the
// replay op completes would go unseen. Read the count, wait out that window, require it
// to be unchanged.
async function settledNotifications(
    client: SignifyClient,
    route: string,
    settleMs = 3000
) {
    const read = async () => {
        const { notes } = await client.notifications().list();
        return notes.filter(
            (note: { a: { r: string }; r: boolean }) =>
                note.a.r === route && note.r === false
        );
    };

    const before = await read();
    await new Promise((resolve) => setTimeout(resolve, settleMs));
    const after = await read();

    assert.equal(
        after.length,
        before.length,
        `notification count for ${route} grew from ${before.length} to ${after.length} after replay`
    );
    return after;
}

let issuerClient: SignifyClient;
let holderClient: SignifyClient;
let issuerAid: Aid;
let holderAid: Aid;

beforeAll(async () => {
    [issuerClient, holderClient] = await getOrCreateClients(2);
});

beforeAll(async () => {
    [issuerAid, holderAid] = await Promise.all([
        createAid(issuerClient, 'issuer'),
        createAid(holderClient, 'holder'),
    ]);

    await Promise.all([
        getOrCreateContact(issuerClient, 'holder', holderAid.oobi),
        getOrCreateContact(holderClient, 'issuer', issuerAid.oobi),
        resolveOobi(issuerClient, QVI_SCHEMA_URL),
        resolveOobi(holderClient, QVI_SCHEMA_URL),
    ]);
});

afterAll(async () => {
    await assertOperations(issuerClient, holderClient);
    await assertNotifications(issuerClient, holderClient);
});

test('KERIA write endpoints are idempotent on replay', async () => {
    const registryName = `registry-${randomUUID()}`;
    let regk: string;
    let credentialId: string;
    let issueArgs: CredentialData;
    let issueOpName: string;
    let anchorPoint: { sn: number; d: string };
    let revSaid: string;

    const registryOpName = await step('registry creation replays', async () => {
        const result = await issuerClient
            .registries()
            .create({ name: issuerAid.name, registryName });
        const op = await result.op();
        await waitOperation(issuerClient, op);
        regk = result.regser.pre;

        const before = await issuerClient.registries().list(issuerAid.name);

        const hab = await issuerClient.identifiers().get(issuerAid.name);
        const res = await issuerClient
            .registries()
            .createFromEvents(
                hab,
                issuerAid.name,
                registryName,
                result.regser.ked,
                result.serder.ked,
                result.sigs
            );

        assert.equal(res.status, 202);
        const replayed = await res.json();
        assert.equal(replayed.name, op.name);
        await waitOperation(issuerClient, replayed);

        const after = await issuerClient.registries().list(issuerAid.name);
        assert.equal(after.length, before.length);

        return op.name as string;
    });
    assert.ok(registryOpName.startsWith('registry.'));

    await step('registry creation rejects a different vcp — 409', async () => {
        const before = await issuerClient.registries().list(issuerAid.name);

        // A fresh create() under the same name mints a new nonce, so the vcp differs.
        // create() does not await the POST, so the rejection only surfaces on op().
        await assert.rejects(
            async () => {
                const conflict = await issuerClient
                    .registries()
                    .create({ name: issuerAid.name, registryName });
                await conflict.op();
            },
            (err: Error) => {
                assert.match(err.message, /409/);
                return true;
            }
        );

        const after = await issuerClient.registries().list(issuerAid.name);
        assert.equal(after.length, before.length);
    });

    await step('credential issuance replays', async () => {
        const hab = await issuerClient.identifiers().get(issuerAid.name);
        anchorPoint = {
            sn: parseInt(hab.state.s, 16),
            d: hab.state.d as string,
        };
        issueArgs = {
            ri: regk,
            s: QVI_SCHEMA_SAID,
            a: {
                i: holderAid.prefix,
                dt: createTimestamp(),
                LEI: '5493001KJTIIGC8Y1R17',
            },
        };
        const args = issueArgs;

        const first = await issuerClient
            .credentials()
            .issue(issuerAid.name, args);
        await waitOperation(issuerClient, first.op);
        credentialId = first.acdc.ked.d as string;
        issueOpName = first.op.name as string;

        // Same anchor point and same dt reproduce the identical acdc, iss and ixn, so this
        // is a true replay rather than a fresh issuance.
        const replay = await issuerClient
            .credentials()
            .issue(issuerAid.name, args, anchorPoint);

        assert.equal(replay.acdc.ked.d, credentialId);
        assert.equal(replay.op.name, first.op.name);
        await waitOperation(issuerClient, replay.op);

        const credentials = await issuerClient.credentials().list();
        assert.equal(
            credentials.filter(
                (c: { sad: { d: string } }) => c.sad.d === credentialId
            ).length,
            1
        );
    });

    await step(
        'credential issuance replays after the KEL advanced',
        async () => {
            // Registrar.issue anchors with the current KEL head rather than the ixn in the
            // request, so a replay that reaches it escrows against an event with no seal.
            const before = await issuerClient.identifiers().get(issuerAid.name);
            const second = await issuerClient
                .credentials()
                .issue(issuerAid.name, {
                    ...issueArgs,
                    a: { ...issueArgs.a, dt: createTimestamp() },
                });
            await waitOperation(issuerClient, second.op);

            const advanced = await issuerClient
                .identifiers()
                .get(issuerAid.name);
            assert.notEqual(advanced.state.s, before.state.s);

            const late = await issuerClient
                .credentials()
                .issue(issuerAid.name, issueArgs, anchorPoint);
            assert.equal(late.acdc.ked.d, credentialId);
            assert.equal(late.op.name, issueOpName);
            await waitOperation(issuerClient, late.op);

            // The stale ixn must not be applied and no new anchor may be written.
            const settled = await issuerClient
                .identifiers()
                .get(issuerAid.name);
            assert.equal(settled.state.s, advanced.state.s);
            assert.equal(settled.state.d, advanced.state.d);

            const credentials = await issuerClient.credentials().list();
            assert.equal(
                credentials.filter(
                    (c: { sad: { d: string } }) => c.sad.d === credentialId
                ).length,
                1
            );
        }
    );

    await step('credential revocation replays', async () => {
        const first = await issuerClient
            .credentials()
            .revoke(issuerAid.name, credentialId, createTimestamp());
        await waitOperation(issuerClient, first.op);

        // revoke() derives the rev event's `p` from the credential's current status, which
        // the first revocation has already advanced, so calling it again builds a different
        // event. A real retry resends the original body, so replay at the transport level.
        const hab = await issuerClient.identifiers().get(issuerAid.name);
        const keeper = issuerClient.manager!.get(hab);
        const sigs = await keeper.sign(b(first.anc.raw));
        const res = await issuerClient.fetch(
            `/identifiers/${issuerAid.name}/credentials/${credentialId}`,
            'DELETE',
            {
                rev: first.rev.ked,
                ixn: first.anc.ked,
                sigs,
                [keeper.algo]: keeper.params(),
            },
            new Headers({ Accept: 'application/json+cesr' })
        );

        assert.equal(res.status, 200);
        const replayed = await res.json();
        assert.equal(replayed.name, first.op.name);
        await waitOperation(issuerClient, replayed);

        const credential = await issuerClient.credentials().get(credentialId);
        assert.equal(credential.status.s, '1');
        assert.equal(credential.status.d, first.rev.ked.d);
        revSaid = first.rev.ked.d as string;
    });

    await step(
        'credential revocation rejects a different rev — 409',
        async () => {
            // revoke() rebuilds the rev from the now-advanced status, so it produces a
            // different event at the same sn.
            await assert.rejects(
                () =>
                    issuerClient
                        .credentials()
                        .revoke(
                            issuerAid.name,
                            credentialId,
                            createTimestamp()
                        ),
                (err: Error) => {
                    assert.match(err.message, /409/);
                    return true;
                }
            );

            const after = await issuerClient.credentials().get(credentialId);
            assert.equal(after.status.d, revSaid);
        }
    );

    await step(
        'exn creation replays without a duplicate notification',
        async () => {
            const hab = await issuerClient.identifiers().get(issuerAid.name);
            const [exn, sigs, atc] = await issuerClient
                .exchanges()
                .createExchangeMessage(
                    hab,
                    '/hmessage',
                    { m: `hello ${randomUUID()}` },
                    {},
                    holderAid.prefix
                );

            const first = await issuerClient
                .exchanges()
                .sendFromEvents(issuerAid.name, 'credential', exn, sigs, atc, [
                    holderAid.prefix,
                ]);
            await waitOperation(issuerClient, first);

            // The sender parses its own exn, so both agents notify.
            assert.equal(
                (await waitForNotifications(holderClient, '/exn/hmessage'))
                    .length,
                1
            );
            assert.equal(
                (await waitForNotifications(issuerClient, '/exn/hmessage'))
                    .length,
                1
            );

            const replay = await issuerClient
                .exchanges()
                .sendFromEvents(issuerAid.name, 'credential', exn, sigs, atc, [
                    holderAid.prefix,
                ]);
            assert.equal(replay.name, first.name);
            await waitOperation(issuerClient, replay);

            for (const client of [holderClient, issuerClient]) {
                const notes = await settledNotifications(
                    client,
                    '/exn/hmessage'
                );
                assert.equal(notes.length, 1);
                for (const note of notes) {
                    await markAndRemoveNotification(client, note);
                }
            }
        }
    );
});

test('full accept dispatch replays with no new artifacts', async () => {
    const registryName = `accept-${randomUUID()}`;
    const dt = createTimestamp();

    let regk: string;
    let credentialId: string;
    let anchorPoint: { sn: number; d: string };
    let args: CredentialData;
    let issuerHab: any;

    let reg: any;
    let regOp: any;
    let issued: any;
    let grant: Serder, gsigs: string[], gend: string;
    let grantOp: any;
    let admit: Serder, asigs: string[], aend: string;
    let admitOp: any;

    await step('dispatch runs once', async () => {
        reg = await issuerClient
            .registries()
            .create({ name: issuerAid.name, registryName });
        regOp = await reg.op();
        await waitOperation(issuerClient, regOp);
        regk = reg.regser.pre;

        issuerHab = await issuerClient.identifiers().get(issuerAid.name);
        anchorPoint = {
            sn: parseInt(issuerHab.state.s, 16),
            d: issuerHab.state.d as string,
        };
        args = {
            ri: regk,
            s: QVI_SCHEMA_SAID,
            a: { i: holderAid.prefix, dt, LEI: '5493001KJTIIGC8Y1R17' },
        };

        issued = await issuerClient.credentials().issue(issuerAid.name, args);
        await waitOperation(issuerClient, issued.op);
        credentialId = issued.acdc.ked.d as string;

        const cred = await issuerClient.credentials().get(credentialId);
        [grant, gsigs, gend] = await issuerClient.ipex().grant({
            senderName: issuerAid.name,
            acdc: new Serder(cred.sad),
            anc: new Serder(cred.anc),
            iss: new Serder(cred.iss),
            ancAttachment: cred.ancAttachment,
            recipient: holderAid.prefix,
            datetime: dt,
        });
        grantOp = await issuerClient
            .ipex()
            .submitGrant(issuerAid.name, grant, gsigs, gend, [
                holderAid.prefix,
            ]);
        await waitOperation(issuerClient, grantOp);

        const grantNote = (
            await waitForNotifications(holderClient, '/exn/ipex/grant')
        )[0];
        [admit, asigs, aend] = await holderClient.ipex().admit({
            senderName: holderAid.name,
            message: '',
            grantSaid: grantNote.a.d!,
            recipient: issuerAid.prefix,
            datetime: dt,
        });
        admitOp = await holderClient
            .ipex()
            .submitAdmit(holderAid.name, admit, asigs, aend, [
                issuerAid.prefix,
            ]);
        await waitOperation(holderClient, admitOp);
        await waitForNotifications(issuerClient, '/exn/ipex/admit');
    });

    await step('same dispatch replayed end to end', async () => {
        const regsBefore = (
            await issuerClient.registries().list(issuerAid.name)
        ).length;
        const issuerCredsBefore = (await issuerClient.credentials().list())
            .length;
        const holderCredsBefore = (await holderClient.credentials().list())
            .length;

        const regReplay = await issuerClient
            .registries()
            .createFromEvents(
                issuerHab,
                issuerAid.name,
                registryName,
                reg.regser.ked,
                reg.serder.ked,
                reg.sigs
            );
        assert.equal(regReplay.status, 202);
        const replayedReg = await regReplay.json();
        assert.equal(replayedReg.name, regOp.name);
        await waitOperation(issuerClient, replayedReg);

        const issueReplay = await issuerClient
            .credentials()
            .issue(issuerAid.name, args, anchorPoint);
        assert.equal(issueReplay.acdc.ked.d, credentialId);
        assert.equal(issueReplay.op.name, issued.op.name);
        await waitOperation(issuerClient, issueReplay.op);

        const grantReplay = await issuerClient
            .ipex()
            .submitGrant(issuerAid.name, grant, gsigs, gend, [
                holderAid.prefix,
            ]);
        assert.equal(grantReplay.name, grantOp.name);
        await waitOperation(issuerClient, grantReplay);

        const admitReplay = await holderClient
            .ipex()
            .submitAdmit(holderAid.name, admit, asigs, aend, [
                issuerAid.prefix,
            ]);
        assert.equal(admitReplay.name, admitOp.name);
        await waitOperation(holderClient, admitReplay);

        assert.equal(
            (await issuerClient.registries().list(issuerAid.name)).length,
            regsBefore
        );
        assert.equal(
            (await issuerClient.credentials().list()).length,
            issuerCredsBefore
        );
        assert.equal(
            (await holderClient.credentials().list()).length,
            holderCredsBefore
        );

        const holderNotes = await settledNotifications(
            holderClient,
            '/exn/ipex/grant'
        );
        assert.equal(holderNotes.length, 1);
        const issuerNotes = await settledNotifications(
            issuerClient,
            '/exn/ipex/admit'
        );
        assert.equal(issuerNotes.length, 1);

        for (const note of holderNotes) {
            await markAndRemoveNotification(holderClient, note);
        }
        for (const note of issuerNotes) {
            await markAndRemoveNotification(issuerClient, note);
        }
    });
});
