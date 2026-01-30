#!/usr/bin/env node

/**
 * Syncs the version across all packages:
 * - Main package.json
 * - All platform packages in npm/
 * - optionalDependencies in main package.json
 *
 * Usage: node scripts/sync-versions.mjs <version>
 *
 * Example: node scripts/sync-versions.mjs 0.2.0
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const nodeDir = join(__dirname, '..');
const npmDir = join(nodeDir, 'npm');

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function writeJson(path, data) {
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n');
}

function discoverPlatformPackages() {
  if (!existsSync(npmDir)) {
    return [];
  }

  return readdirSync(npmDir)
    .filter(name => {
      const pkgPath = join(npmDir, name, 'package.json');
      return existsSync(pkgPath) && statSync(join(npmDir, name)).isDirectory();
    });
}

function main() {
  const newVersion = process.argv[2];

  if (!newVersion) {
    console.error('Usage: node scripts/sync-versions.mjs <version>');
    console.error('Example: node scripts/sync-versions.mjs 0.2.0');
    process.exit(1);
  }

  // Validate version format (basic semver check)
  if (!/^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(newVersion)) {
    console.error(`Invalid version format: ${newVersion}`);
    console.error('Expected semver format: X.Y.Z or X.Y.Z-prerelease');
    process.exit(1);
  }

  console.log(`Setting all packages to version ${newVersion}\n`);

  // Update main package.json
  const mainPkgPath = join(nodeDir, 'package.json');
  const mainPkg = readJson(mainPkgPath);
  mainPkg.version = newVersion;

  // Update optionalDependencies versions
  if (mainPkg.optionalDependencies) {
    for (const name of Object.keys(mainPkg.optionalDependencies)) {
      mainPkg.optionalDependencies[name] = newVersion;
    }
    console.log(`Updated main package.json (version + ${Object.keys(mainPkg.optionalDependencies).length} optionalDependencies)`);
  } else {
    console.log('Updated main package.json');
  }

  writeJson(mainPkgPath, mainPkg);

  // Discover and update all platform packages
  const platforms = discoverPlatformPackages();

  for (const platform of platforms) {
    const pkgPath = join(npmDir, platform, 'package.json');
    const pkg = readJson(pkgPath);
    pkg.version = newVersion;
    writeJson(pkgPath, pkg);
    console.log(`Updated npm/${platform}/package.json`);
  }

  console.log(`\nDone! ${platforms.length + 1} packages updated to version ${newVersion}`);
}

main();
