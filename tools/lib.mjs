// Shared by encrypt.mjs / decrypt.mjs: argument parsing, password input, key derivation, blob opening.
// Must stay byte-compatible with the derivation in index.html (PBKDF2-SHA256 -> HKDF-SHA256 -> AES-256-GCM).
import crypto from 'node:crypto';

export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) throw new Error(`unexpected argument: ${a}`);
    const next = argv[i + 1];
    out[a.slice(2)] = next !== undefined && !next.startsWith('--') ? argv[++i] : true;
  }
  return out;
}

// ALBUM_PASSWORD from the environment, otherwise a hidden prompt on a terminal. Never a CLI flag (shell history).
export function getPassword() {
  if (process.env.ALBUM_PASSWORD) return Promise.resolve(process.env.ALBUM_PASSWORD);
  if (!process.stdin.isTTY) return Promise.reject(new Error('set ALBUM_PASSWORD (no terminal to prompt on)'));
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let buf = '';
    process.stdout.write('password: ');
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const done = (fn) => { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); process.stdout.write('\n'); fn(); };
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') return done(() => (buf ? resolve(buf) : reject(new Error('empty password'))));
        if (c === '\u0003') return done(() => reject(new Error('aborted')));
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1); else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

// password + salt -> { enc: AES-256-GCM key, aux: HMAC key for blob ids / IVs (build side only) }
export function deriveKeys(password, salt, iterations) {
  const master = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), salt, iterations, 32, 'sha256');
  const sub = (info) => Buffer.from(crypto.hkdfSync('sha256', master, new Uint8Array(0), info, 32));
  return { enc: sub('album-enc'), aux: sub('album-aux') };
}

// blob layout: 12-byte IV | ciphertext | 16-byte GCM tag. Throws on a wrong key or any tampering.
export function unseal(encKey, blob) {
  if (blob.length < 28) throw new Error('blob too short');
  const d = crypto.createDecipheriv('aes-256-gcm', encKey, blob.subarray(0, 12));
  d.setAuthTag(blob.subarray(blob.length - 16));
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]);
}
