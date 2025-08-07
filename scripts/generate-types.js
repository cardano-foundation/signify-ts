import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const specUrl = process.env.SPEC_URL;
const outputFile = path.resolve('src/types/keria-api-schema.ts');

if (!specUrl) {
    console.log('⚠️  Skipping OpenAPI type generation: SPEC_URL is not set.');
    process.exit(0);
}

console.log(`📦 Generating types from ${specUrl}`);
execSync(`npx openapi-typescript "${specUrl}" --output ${outputFile} --enum`, {
    stdio: 'inherit',
});

// Read the full file
const fullContent = fs.readFileSync(outputFile, 'utf8');

// Extract the `export interface components { ... }` block
const componentsMatch = fullContent.match(/export interface components \{[\s\S]+?\n\}/);

// Extract all `export enum ... { ... }` blocks
const enumMatches = [...fullContent.matchAll(/export enum [\w\d_]+ \{[\s\S]+?\n\}/g)];

if (!componentsMatch) {
    console.error("❌ Could not find 'export interface components' block.");
    process.exit(1);
}

// Combine the interface and enums
const enumsText = enumMatches.map(m => m[0]).join('\n\n');
const cleaned = `// AUTO-GENERATED: Only components and enums retained from OpenAPI schema\n\n${enumsText}\n\n${componentsMatch[0]}\n`;

fs.writeFileSync(outputFile, cleaned, 'utf8');
