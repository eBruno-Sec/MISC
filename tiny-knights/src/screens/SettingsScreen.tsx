import { useState } from 'react';
import type { UserProgress } from '../types';
import MonsterBook from '../components/MonsterBook';
import { useKnightsPass } from '../lib/entitlements';

type SettingsScreenProps = {
  progress: UserProgress;
  onUpdateProgress: (progress: UserProgress) => void;
  onBack: () => void;
};

export default function SettingsScreen({ progress, onUpdateProgress, onBack }: SettingsScreenProps) {
  const [nameInput, setNameInput] = useState(progress.childName);
  const { passActive } = useKnightsPass();

  function toggle(key: 'soundEnabled' | 'reducedMotion' | 'darkMode') {
    onUpdateProgress({
      ...progress,
      settings: { ...progress.settings, [key]: !progress.settings[key] },
    });
  }

  function setDifficulty(difficulty: UserProgress['settings']['difficulty']) {
    onUpdateProgress({
      ...progress,
      settings: { ...progress.settings, difficulty },
    });
  }

  function handleNameChange(name: string) {
    setNameInput(name);
  }

  function handleNameBlur() {
    const finalName = nameInput.trim() || 'Knight';
    setNameInput(finalName);
    if (finalName !== progress.childName) {
      onUpdateProgress({ ...progress, childName: finalName });
    }
  }

  return (
    <div className="min-h-dvh flex flex-col gap-6 px-4 py-6 max-w-xl mx-auto pb-8">
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="rounded-full bg-white border-2 border-gray-200 w-10 h-10 flex items-center justify-center text-xl shadow-sm hover:bg-gray-50"
          aria-label="Back to home"
        >
          ←
        </button>
        <h1 className="font-display text-2xl md:text-3xl font-extrabold text-knight-blue-dark">Settings</h1>
      </div>

      <section className="rounded-2xl bg-white border-2 border-gray-100 p-4 flex flex-col gap-4">
        <div>
          <label htmlFor="childName" className="block text-sm font-bold text-gray-700 mb-1">
            Knight's Name
          </label>
          <input
            id="childName"
            type="text"
            value={nameInput}
            onChange={(e) => handleNameChange(e.target.value)}
            onBlur={handleNameBlur}
            maxLength={20}
            className="w-full rounded-xl border-2 border-gray-200 px-3 py-2 text-base font-bold"
          />
        </div>

        <div className="flex items-center justify-between gap-4">
          <span className="text-sm font-bold text-gray-700">Sound Effects</span>
          <button
            role="switch"
            aria-checked={progress.settings.soundEnabled}
            onClick={() => toggle('soundEnabled')}
            className={`relative w-14 h-8 rounded-full transition-colors ${
              progress.settings.soundEnabled ? 'bg-hp-green' : 'bg-gray-300'
            }`}
          >
            <span
              className={`absolute top-1 left-1 w-6 h-6 rounded-full bg-white shadow transition-transform ${
                progress.settings.soundEnabled ? 'translate-x-6' : ''
              }`}
            />
          </button>
        </div>

        <div className="flex items-center justify-between gap-4">
          <span className="text-sm font-bold text-gray-700">Reduce Motion</span>
          <button
            role="switch"
            aria-checked={progress.settings.reducedMotion}
            onClick={() => toggle('reducedMotion')}
            className={`relative w-14 h-8 rounded-full transition-colors ${
              progress.settings.reducedMotion ? 'bg-hp-green' : 'bg-gray-300'
            }`}
          >
            <span
              className={`absolute top-1 left-1 w-6 h-6 rounded-full bg-white shadow transition-transform ${
                progress.settings.reducedMotion ? 'translate-x-6' : ''
              }`}
            />
          </button>
        </div>

        <div className="flex items-center justify-between gap-4">
          <span className="text-sm font-bold text-gray-700">🌙 Dark Mode</span>
          <button
            role="switch"
            aria-checked={progress.settings.darkMode}
            onClick={() => toggle('darkMode')}
            className={`relative w-14 h-8 rounded-full transition-colors ${
              progress.settings.darkMode ? 'bg-hp-green' : 'bg-gray-300'
            }`}
          >
            <span
              className={`absolute top-1 left-1 w-6 h-6 rounded-full bg-white shadow transition-transform ${
                progress.settings.darkMode ? 'translate-x-6' : ''
              }`}
            />
          </button>
        </div>

        <div>
          <span className="block text-sm font-bold text-gray-700 mb-2">Difficulty (response speed goal)</span>
          <div className="grid grid-cols-3 gap-2">
            {(['easy', 'normal', 'challenge'] as const).map((d) => (
              <button
                key={d}
                onClick={() => setDifficulty(d)}
                className={`rounded-xl border-2 py-3 font-bold capitalize text-sm transition-all ${
                  progress.settings.difficulty === d
                    ? 'bg-knight-blue text-white border-knight-blue'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-knight-blue/40'
                }`}
              >
                {d}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section>
        <h2 className="font-display text-xl font-bold text-gray-700 mb-3">Monster Book</h2>
        <MonsterBook entries={progress.monsterBook} maxFactor={progress.maxFactor} />
      </section>

      <section>
        <h2 className="font-display text-xl font-bold text-gray-700 mb-3">Your Gear</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {progress.cosmetics.map((c) => {
            const unlocked = !!c.unlockedAt || (c.premium && passActive);
            return (
              <div
                key={c.id}
                className={`flex flex-col items-center gap-1 rounded-2xl border-2 p-3 text-center ${
                  unlocked ? 'bg-purple-50 border-purple-300' : 'bg-gray-50 border-gray-200'
                }`}
              >
                <span className={`text-2xl ${unlocked ? '' : 'opacity-30 grayscale'}`} aria-hidden="true">
                  {c.icon}
                </span>
                <span className={`text-xs font-bold ${unlocked ? 'text-purple-700' : 'text-gray-400'}`}>
                  {c.name}
                </span>
                {c.premium && !unlocked && (
                  <span className="text-[10px] font-bold text-amber-600">👑 Knight's Pass</span>
                )}
              </div>
            );
          })}
        </div>
      </section>

      <section>
        <h2 className="font-display text-xl font-bold text-gray-700 mb-3">Your Badges</h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          {progress.badges.map((b) => (
            <div
              key={b.id}
              className={`flex flex-col items-center gap-1 rounded-2xl border-2 p-3 text-center ${
                b.earnedAt ? 'bg-amber-50 border-amber-300' : 'bg-gray-50 border-gray-200'
              }`}
            >
              <span className={`text-2xl ${b.earnedAt ? '' : 'opacity-30 grayscale'}`} aria-hidden="true">
                {b.icon}
              </span>
              <span className={`text-xs font-bold ${b.earnedAt ? 'text-amber-700' : 'text-gray-400'}`}>
                {b.name}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
