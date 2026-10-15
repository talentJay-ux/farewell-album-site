#!/usr/bin/env node
// Recover the plaintext album from a published site (the inverse of encrypt.mjs):
//
//   ALBUM_PASSWORD=... node tools/decrypt.mjs [--site .] --out <dir>
//
// Writes <dir>/album.json and every photo / music file at its original path. Fails loudly on a wrong
// password (every blob is authenticated) or on a missing / corrupted blob.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { parseArgs, getPassword, deriveKeys, unseal } from './lib.mjs';

const args = parseArgs(process.argv.slice(2));
if (!args.out || args.out === true) throw new Error('--out <dir> is required');
const SITE = resolve(args.site || '.');
const OUT = resolve(args.out);

const M = JSON.parse(readFileSync(join(SITE, 'manifest.json'), 'utf8'));
if (M.v !== 1 || !M.kdf || M.kdf.alg !== 'PBKDF2-SHA256') throw new Error('unsupported manifest');
const { enc } = deriveKeys(await getPassword(), Buffer.from(M.kdf.salt, 'base64'), M.kdf.iter);
const read = (id) => {
  try { return unseal(enc, readFileSync(join(SITE, id))); }
  catch (e) { throw new Error(`cannot decrypt ${id}: ${e.message} (wrong password, or the blob is corrupted)`); }
};

const { files, ...album } = JSON.parse(read(M.data).toString('utf8'));
for (const [path, id] of Object.entries(files)) {
  const dest = join(OUT, path);
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, read(id));
}
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'album.json'), JSON.stringify(album, null, 1) + '\n');
console.log(`${Object.keys(files).length} files + album.json -> ${OUT}`);
