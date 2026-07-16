import { SignifyClient } from 'signify-ts';
import {
    getOrCreateClients,
    getOrCreateIdentifier,
    waitOperation,
} from './utils/test-util';

let client1: SignifyClient;

beforeAll(async () => {
    [client1] = await getOrCreateClients(1);
});

interface KeyState {
    s: string;
    k: string[];
    n: string[];
    [property: string]: any;
}

describe('rotation resubmit', () => {
    test('resubmitting the same rotation event is idempotent', async () => {
        const [aid] = await getOrCreateIdentifier(client1, 'rotidem');

        const data = await client1.identifiers().createRotationData('rotidem');
        const first = await client1
            .identifiers()
            .submitRotationData('rotidem', data);
        await waitOperation(client1, await first.op());

        const afterFirst: KeyState = (await client1.keyStates().get(aid)).at(0);
        expect(afterFirst.s).toEqual('1');

        // resubmit the identical event, this is what a client retry does.
        // if KERIA rejected a resubmit, this line would throw
        const second = await client1
            .identifiers()
            .submitRotationData('rotidem', data);
        await second.op();

        // the resubmit left the KEL untouched
        const afterSecond: KeyState = (await client1.keyStates().get(aid)).at(
            0
        );
        expect(afterSecond.s).toEqual(afterFirst.s);
        expect(afterSecond.k).toEqual(afterFirst.k);
        expect(afterSecond.n).toEqual(afterFirst.n);

        // and the keeper is still in sync, so the next rotation works
        const data2 = await client1.identifiers().createRotationData('rotidem');
        const third = await client1
            .identifiers()
            .submitRotationData('rotidem', data2);
        await waitOperation(client1, await third.op());

        const afterThird: KeyState = (await client1.keyStates().get(aid)).at(0);
        expect(afterThird.s).toEqual('2');
        expect(afterThird.k).not.toEqual(afterFirst.k);
    });
});
