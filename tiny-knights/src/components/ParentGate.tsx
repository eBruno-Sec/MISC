import { useState } from 'react';

type ParentGateProps = {
  onPass: () => void;
  onBack: () => void;
};

function makeChallenge() {
  const a = 6 + Math.floor(Math.random() * 4); // 6-9
  const b = 6 + Math.floor(Math.random() * 4);
  return { a, b };
}

/**
 * Simple grown-ups-only gate in front of the Parent Dashboard: keeps kids away
 * from settings, progress reset, and anything purchase-related.
 */
export default function ParentGate({ onPass, onBack }: ParentGateProps) {
  const [challenge, setChallenge] = useState(makeChallenge);
  const [value, setValue] = useState('');
  const [shake, setShake] = useState(false);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (Number(value) === challenge.a * challenge.b) {
      onPass();
      return;
    }
    setChallenge(makeChallenge());
    setValue('');
    setShake(true);
    setTimeout(() => setShake(false), 500);
  }

  return (
    <div className="min-h-dvh flex flex-col items-center justify-center gap-6 px-4 py-6 max-w-md mx-auto text-center">
      <div className="text-5xl" aria-hidden="true">🔒</div>
      <h1 className="font-display text-2xl font-extrabold text-knight-blue-dark">Grown-Ups Only</h1>
      <p className="text-gray-600 font-semibold">
        This area is for parents. To continue, answer:
      </p>
      <form
        onSubmit={handleSubmit}
        className={`flex flex-col items-center gap-4 w-full ${shake ? 'animate-damage-shake' : ''}`}
      >
        <div className="font-display text-4xl font-extrabold text-gray-800 tabular-nums">
          {challenge.a} × {challenge.b} = ?
        </div>
        <input
          type="text"
          inputMode="numeric"
          pattern="[0-9]*"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value.replace(/\D/g, '').slice(0, 3))}
          className="w-32 text-center rounded-xl border-2 border-gray-300 px-3 py-3 font-display text-2xl font-extrabold"
          aria-label="Your answer"
        />
        <button
          type="submit"
          className="w-full max-w-xs rounded-2xl bg-knight-blue text-white font-display font-extrabold text-lg py-3 shadow-md hover:bg-knight-blue-dark transition-colors"
        >
          Enter
        </button>
      </form>
      <button onClick={onBack} className="text-sm text-gray-400 underline hover:text-gray-600">
        Back to the castle
      </button>
    </div>
  );
}
