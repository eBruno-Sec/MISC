import { useEffect, useState } from 'react';

/**
 * Knight's Pass — one-time supporter unlock, activated with a code the buyer
 * receives after purchase. Codes are validated offline against SHA-256 hashes,
 * so no backend is needed. The pass is stored separately from game progress so
 * "Reset All Progress" never revokes a purchase.
 *
 * To sell passes: set KNIGHTS_PASS_URL to your product page (Stripe Payment
 * Link, Gumroad, Ko-fi...) and deliver one of the codes on purchase. To mint
 * new codes: sha256(code.toUpperCase().replace(/[^A-Z0-9]/g, '')) and append
 * the hex digest to VALID_CODE_HASHES, e.g.
 *   node -e "console.log(require('crypto').createHash('sha256').update('TINY-AAAA-BBBB').digest('hex'))"
 */
export const KNIGHTS_PASS_URL = ''; // TODO: set to your purchase page to show a "Get the Pass" button

const PASS_STORAGE_KEY = 'tiny-knights-pass-v1';
const PASS_CHANGE_EVENT = 'tiny-knights-pass-change';

const VALID_CODE_HASHES = [
  'c69dd76c556017806171d4c1401f48efc82105dbc2c7742710a317f849d7f7b6',
  'e166c3ea99cdb089ea7eafa95c8dd23b19bd06d4f1ede77727dc2b6c692d8294',
  'ab643f3c407110e0805606c4a31b673e5557558382f460d7191bcbf6a2e63385',
  'af53f5f015f1d426167d0023f19a6ad1e3020e57c6f4bfc3cae2cac5bcd88cef',
  '362cc0a9ac05137a7fcbb6589120dc127ba8f75c76fef66e8bb4811d7d0d746b',
  '97daebf3eb20c9c357500b1ea32f6219fd36a2c406ce51808ef0318ea2f4421b',
];

function normalizeCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function isPassActive(): boolean {
  try {
    return localStorage.getItem(PASS_STORAGE_KEY) !== null;
  } catch {
    return false;
  }
}

export async function activatePass(code: string): Promise<boolean> {
  const normalized = normalizeCode(code);
  if (!normalized) return false;
  const hash = await sha256Hex(normalized);
  if (!VALID_CODE_HASHES.includes(hash)) return false;
  try {
    localStorage.setItem(PASS_STORAGE_KEY, JSON.stringify({ activatedAt: new Date().toISOString() }));
  } catch {
    return false;
  }
  window.dispatchEvent(new Event(PASS_CHANGE_EVENT));
  return true;
}

/** React hook: live view of pass state plus an activate function. */
export function useKnightsPass(): {
  passActive: boolean;
  activate: (code: string) => Promise<boolean>;
} {
  const [passActive, setPassActive] = useState(() => isPassActive());

  useEffect(() => {
    const update = () => setPassActive(isPassActive());
    window.addEventListener(PASS_CHANGE_EVENT, update);
    window.addEventListener('storage', update);
    return () => {
      window.removeEventListener(PASS_CHANGE_EVENT, update);
      window.removeEventListener('storage', update);
    };
  }, []);

  return { passActive, activate: activatePass };
}
