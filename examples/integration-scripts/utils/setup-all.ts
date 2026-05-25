/**
 * Runs the full setup pipeline for WAP group issuance tests.
 *
 * Order:
 *   1. create-test-clients.ts  -> .test-clients.json
 *   2. create-test-multisig.ts -> .test-group.json
 *   3. create-test-contacts.ts -> .test-contacts.json
 *
 * Run after `docker-compose down -v && docker-compose up -d`.
 *
 * Usage:
 *   cd signify-ts
 *   npx tsx examples/integration-scripts/utils/setup-all.ts
 *
 * Env vars (forwarded to children):
 *   N_MEMBERS  number of multisig members (default 2)
 *   THRESHOLD  signing threshold (default = N_MEMBERS for full N-of-N)
 *   GROUP_NAME group identifier alias (default G1v2)
 */
import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const examplesDir = path.join(__dirname, '../../');
const staleFiles = [
    '.test-clients.json',
    '.test-group.json',
    '.test-contacts.json',
];

const scripts = [
    'create-test-clients.ts',
    'create-test-multisig.ts',
    'create-test-contacts.ts',
];

function run(script: string): void {
    const fullPath = path.join(__dirname, script);
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Running: ${script}`);
    console.log('='.repeat(60));
    const t0 = Date.now();
    const result = spawnSync('npx', ['tsx', fullPath], { stdio: 'inherit' });
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
    if (result.status !== 0) {
        console.error(`\n${script} FAILED after ${elapsed}s (exit ${result.status})`);
        process.exit(1);
    }
    console.log(`\n${script} done in ${elapsed}s`);
}

async function main(): Promise<void> {
    console.log('WAP E2E test setup pipeline');
    console.log(`Working dir: ${process.cwd()}`);

    // Delete stale JSONs so a partial setup doesn't leave the next run confused
    for (const f of staleFiles) {
        const full = path.join(examplesDir, f);
        if (fs.existsSync(full)) {
            fs.unlinkSync(full);
            console.log(`Removed stale ${f}`);
        }
    }

    const totalT0 = Date.now();

    for (const script of scripts) {
        run(script);
    }

    const total = ((Date.now() - totalT0) / 1000).toFixed(1);
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Setup complete in ${total}s`);
    console.log('='.repeat(60));
    console.log('\nFiles generated:');
    console.log('  examples/.test-clients.json');
    console.log('  examples/.test-group.json');
    console.log('  examples/.test-contacts.json');
    console.log('\nNow run: npm run test:wap-e2e');
}

main().catch((err) => {
    console.error('Setup failed:', err);
    process.exit(1);
});
