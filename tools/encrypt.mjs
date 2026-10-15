#!/usr/bin/env node
// Build step: encrypt the album so the public repo holds nothing readable without the password.
//
//   ALBUM_PASSWORD=... node tools/encrypt.mjs [--src private] [--out .] [--iter 600000] [--new-salt]
//
// Reads <src>/album.json plus every photo / music file it references and writes
//   <out>/b/<id>.bin     one AES-256-GCM blob per file (12-byte IV | ciphertext | 16-byte tag)
//   <out>/manifest.json  public: KDF parameters, id of the encrypted album.json, blobs worth prefetching
// Ids and IVs are keyed HMACs of each file's plaintext, so the build is deterministic (rebuilding an
// unchanged album is a no-op in git) and content-addressed (a changed photo gets a new id, so no cache
// can serve a stale one). Blobs that are no longer referenced are deleted from <out>/b/.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, unlinkSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import crypto from 'node:crypto';
import { parseArgs, getPassword, deriveKeys } from './lib.mjs';

const args = parseArgs(process.argv.slice(2));
const SRC = resolve(args.src || 'private');
const OUT = resolve(args.out || '.');
const ITER = Number(args.iter || 600000);
if (!Number.isInteger(ITER) || ITER < 100000) throw new Error('--iter must be an integer >= 100000');

const album = JSON.parse(readFileSync(join(SRC, 'album.json'), 'utf8'));
if ('files' in album) throw new Error('album.json must not contain a "files" key (it is generated)');
const refs = [album.cover, album.music];
for (const p of album.photos) refs.push(p.src, p.thumb, p.blur);
for (const r of refs) if (typeof r !== 'string' || !r) throw new Error('album.json references an empty path');
const paths = [...new Set(refs)];
for (const p of paths) if (!existsSync(join(SRC, p))) throw new Error(`missing file: ${join(SRC, p)}`);

// Reuse the published salt so the key, and with it every blob id, stays stable across rebuilds.
const manifestPath = join(OUT, 'manifest.json');
let salt = null;
if (!args['new-salt'] && existsSync(manifestPath)) {
  const old = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (old.kdf && old.kdf.salt) salt = Buffer.from(old.kdf.salt, 'base64');
}
if (!salt) salt = crypto.randomBytes(16);

const password = await getPassword();
const t0 = Date.now();
const { enc, aux } = deriveKeys(password, salt, ITER);
const kdfMs = Date.now() - t0;
const hmac = (label, data) => crypto.createHmac('sha256', aux).update(label).update(data).digest();

function seal(plain) {
  const id = 'b/' + hmac('id\0', plain).subarray(0, 12).toString('hex') + '.bin';
  const iv = hmac('iv\0', plain).subarray(0, 12);
  const c = crypto.createCipheriv('aes-256-gcm', enc, iv);
  const bytes = Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
  return { id, bytes };
}

mkdirSync(join(OUT, 'b'), { recursive: true });
const written = new Set();
let total = 0;
function emit({ id, bytes }) {
  if (!written.has(id)) { writeFileSync(join(OUT, id), bytes); written.add(id); total += bytes.length; }
  return id;
}

const files = {};
for (const p of paths) files[p] = emit(seal(readFileSync(join(SRC, p))));
const data = emit(seal(Buffer.from(JSON.stringify({ ...album, files }), 'utf8')));

const preload = [album.cover, album.music, ...album.photos.slice(0, 3).flatMap((p) => [p.blur, p.src])].map((p) => files[p]);
const manifest = { v: 1, kdf: { alg: 'PBKDF2-SHA256', iter: ITER, salt: salt.toString('base64') }, data, preload: [...new Set(preload)] };
writeFileSync(manifestPath, JSON.stringify(manifest, null, 1) + '\n');

let removed = 0;
for (const f of readdirSync(join(OUT, 'b'))) if (!written.has('b/' + f)) { unlinkSync(join(OUT, 'b', f)); removed++; }

console.log(`key derived in ${kdfMs} ms (${ITER} iterations)`);
console.log(`${paths.length} files + album.json -> ${written.size} blobs, ${(total / 1048576).toFixed(2)} MB; ${removed} stale blob(s) removed`);
console.log(`manifest: ${manifestPath}`);
