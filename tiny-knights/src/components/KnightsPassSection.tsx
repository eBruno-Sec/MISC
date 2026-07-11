import { useState } from 'react';
import { KNIGHTS_PASS_URL, useKnightsPass } from '../lib/entitlements';
import { trackEvent } from '../lib/analytics';

/**
 * Supporter section shown inside the (parent-gated) Parent Dashboard.
 * The child-facing game never shows prices or purchase prompts.
 */
export default function KnightsPassSection() {
  const { passActive, activate } = useKnightsPass();
  const [code, setCode] = useState('');
  const [status, setStatus] = useState<'idle' | 'checking' | 'invalid' | 'success'>('idle');

  async function handleActivate(e: React.FormEvent) {
    e.preventDefault();
    if (!code.trim()) return;
    setStatus('checking');
    const ok = await activate(code);
    setStatus(ok ? 'success' : 'invalid');
    if (ok) {
      setCode('');
      trackEvent('knights-pass-activated');
    }
  }

  if (passActive) {
    return (
      <section className="rounded-2xl bg-amber-50 border-2 border-amber-300 p-4">
        <h3 className="font-display text-lg font-bold text-amber-800">👑 Knight's Pass — Active</h3>
        <p className="text-sm text-amber-800 mt-1">
          Thank you for supporting Tiny Knights! The premium gear pack is unlocked and printable
          progress reports are available above.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-2xl bg-white border-2 border-amber-200 p-4 flex flex-col gap-3">
      <h3 className="font-display text-lg font-bold text-gray-700">👑 Knight's Pass</h3>
      <p className="text-sm text-gray-600">
        Tiny Knights is free, with no ads and no accounts — and it stays that way. The optional
        Knight's Pass supports development and unlocks:
      </p>
      <ul className="text-sm text-gray-600 list-disc pl-5">
        <li>Premium gear pack for your knight (🐉 🦁 ✨ 🔥)</li>
        <li>Printable progress reports &amp; certificates</li>
        <li>First access to new subject packs as they arrive</li>
      </ul>
      {KNIGHTS_PASS_URL && (
        <a
          href={KNIGHTS_PASS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="self-start rounded-xl bg-knight-blue text-white font-bold text-sm px-4 py-2 hover:bg-knight-blue-dark transition-colors"
        >
          Get the Knight's Pass
        </a>
      )}
      <form onSubmit={handleActivate} className="flex flex-wrap items-center gap-2">
        <label htmlFor="passCode" className="text-sm font-semibold text-gray-700 w-full">
          Already have a code?
        </label>
        <input
          id="passCode"
          type="text"
          value={code}
          onChange={(e) => { setCode(e.target.value); setStatus('idle'); }}
          placeholder="TINY-XXXX-XXXX"
          className="flex-1 min-w-40 rounded-xl border-2 border-gray-200 px-3 py-2 text-sm font-bold uppercase"
        />
        <button
          type="submit"
          disabled={status === 'checking'}
          className="rounded-xl bg-hp-green text-white font-bold text-sm px-4 py-2 hover:bg-green-500 transition-colors disabled:opacity-50"
        >
          {status === 'checking' ? 'Checking…' : 'Activate'}
        </button>
        {status === 'invalid' && (
          <p className="w-full text-sm font-semibold text-red-600">
            That code doesn't look right — check for typos and try again.
          </p>
        )}
      </form>
    </section>
  );
}
