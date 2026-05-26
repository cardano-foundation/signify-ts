import { SignifyClient } from 'signify-ts';
import {
    assertOperations,
    getOrCreateClients,
    getOrCreateIdentifier,
} from './utils/test-util';

let client: SignifyClient;
let name: string;
let prefix: string;

beforeAll(async () => {
    [client] = await getOrCreateClients(1);
});

beforeAll(async () => {
    name = 'metadata-test-id';
    [prefix] = await getOrCreateIdentifier(client, name);
});

afterAll(async () => {
    await assertOperations(client);
});

describe('metadata', () => {
    test('create metadata', async () => {
        const metadata = {
            displayName: 'Alice',
            email: 'alice@example.com',
            avatar: 'https://example.com/avatars/alice.jpg',
        };

        const result = await client
            .identifiers()
            .updateMetadata(name, metadata);

        expect(result).toBeDefined();
        expect(result.id).toEqual(prefix);
        expect(result.displayName).toEqual(metadata.displayName);
        expect(result.email).toEqual(metadata.email);
        expect(result.avatar).toEqual(metadata.avatar);
    });

    test('get metadata via identifier get', async () => {
        const hab = await client.identifiers().get(name);
        const metadata = hab.metadata;

        expect(metadata).not.toBeNull();
        expect(metadata!.displayName).toEqual('Alice');
        expect(metadata!.email).toEqual('alice@example.com');
        expect(metadata!.avatar).toEqual(
            'https://example.com/avatars/alice.jpg'
        );
    });

    test('update metadata', async () => {
        const updatedMetadata = {
            displayName: 'Bob',
            email: 'bob@example.com',
            theme: 'dark',
            language: 'en-US',
        };

        const result = await client
            .identifiers()
            .updateMetadata(name, updatedMetadata);

        expect(result).toBeDefined();
        expect(result.id).toEqual(prefix);
        expect(result.displayName).toEqual(updatedMetadata.displayName);
        expect(result.email).toEqual(updatedMetadata.email);
        expect(result.theme).toEqual(updatedMetadata.theme);
        expect(result.language).toEqual(updatedMetadata.language);

        const hab = await client.identifiers().get(name);
        const metadata = hab.metadata;

        expect(metadata).not.toBeNull();
        expect(metadata!.displayName).toEqual('Bob');
        expect(metadata!.email).toEqual('bob@example.com');
        expect(metadata!.theme).toEqual('dark');
        expect(metadata!.language).toEqual('en-US');
    });

    test('partial update metadata', async () => {
        const partialMetadata = {
            displayName: 'Bob',
            email: 'bob@example.com',
            theme: 'dark',
            language: 'en-US',
            fontSize: '14',
            notifications: 'true',
        };

        const result = await client
            .identifiers()
            .updateMetadata(name, partialMetadata);

        expect(result).toBeDefined();
        expect(result.id).toEqual(prefix);
        expect(result.fontSize).toEqual('14');
        expect(result.notifications).toEqual('true');
    });

    test('delete metadata', async () => {
        const result = await client
            .identifiers()
            .updateMetadata(name, {});

        expect(result).toBeDefined();
        expect(result).toEqual({ id: prefix });

        const hab = await client.identifiers().get(name);
        expect(hab.metadata).toEqual({ id: prefix });
    });

    test('recreate metadata after deletion', async () => {
        const newMetadata = {
            displayName: 'Alice',
            role: 'administrator',
            department: 'IT',
        };

        const result = await client
            .identifiers()
            .updateMetadata(name, newMetadata);

        expect(result).toBeDefined();
        expect(result.id).toEqual(prefix);
        expect(result.displayName).toEqual('Alice');
        expect(result.role).toEqual('administrator');
        expect(result.department).toEqual('IT');

        const hab = await client.identifiers().get(name);
        const metadata = hab.metadata;

        expect(metadata).not.toBeNull();
        expect(metadata!.displayName).toEqual('Alice');
        expect(metadata!.role).toEqual('administrator');
        expect(metadata!.department).toEqual('IT');
    });

    test('metadata with identifier prefix instead of alias', async () => {
        const metadata = {
            theme: 'light',
            colorScheme: 'blue',
            sidebarCollapsed: 'false',
        };

        const result = await client
            .identifiers()
            .updateMetadata(prefix, metadata);

        expect(result).toBeDefined();
        expect(result.id).toEqual(prefix);
        expect(result.theme).toEqual('light');
        expect(result.colorScheme).toEqual('blue');
        expect(result.sidebarCollapsed).toEqual('false');

        const hab = await client.identifiers().get(prefix);
        const habMetadata = hab.metadata;

        expect(habMetadata).not.toBeNull();
        expect(habMetadata!.theme).toEqual('light');
    });
});
