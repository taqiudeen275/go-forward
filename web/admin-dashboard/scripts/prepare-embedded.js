#!/usr/bin/env node

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const projectRoot = join(__dirname, '..');
const buildDir = join(projectRoot, 'build');
const embedDir = join(projectRoot, '..', '..', 'internal', 'dashboard', 'embed');

console.log('Preparing embedded assets for Go...');

// Ensure embed directory exists
if (!existsSync(embedDir)) {
    mkdirSync(embedDir, { recursive: true });
}

// Create Go embed file
const embedGoContent = `package dashboard

import "embed"

// Static assets for the admin dashboard
//go:embed build/*
var StaticAssets embed.FS

// GetStaticAssets returns the embedded static assets
func GetStaticAssets() embed.FS {
	return StaticAssets
}
`;

writeFileSync(join(embedDir, 'assets.go'), embedGoContent);

// Copy build directory to embed location
import { execSync } from 'child_process';

try {
    // Remove existing build directory in embed location
    if (existsSync(join(embedDir, 'build'))) {
        execSync(`rmdir /s /q "${join(embedDir, 'build')}"`, { shell: true });
    }
    
    // Copy build directory
    execSync(`xcopy /E /I /Y "${buildDir}" "${join(embedDir, 'build')}"`, { shell: true });
    
    console.log('✅ Embedded assets prepared successfully');
    console.log(`📁 Assets location: ${embedDir}`);
} catch (error) {
    console.error('❌ Error preparing embedded assets:', error.message);
    process.exit(1);
}