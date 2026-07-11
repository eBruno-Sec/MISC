import { useEffect } from 'react';
import type { FactKey, PracticeSession, UserProgress } from '../types';
import { getLevelFromXp } from '../lib/rewards';
import { parseFactKey } from '../lib/facts';
import { playSfx } from '../lib/sound';
import RewardChest from '../components/RewardChest';
import KnightSprite from '../components/KnightSprite';

type VictoryScreenProps = {
  session: PracticeSession;
  xpEarned: number;
  coinsEarned: number;
  newlyEarnedBadges: { id: string; name: string; icon: string }[];
  newlyUnlockedCosmetics: { id: string; name: string; icon: string }[];
  bossWon: boolean;
  progress: UserProgress;
  onContinue: () => void;
  onHome: () => void;
};

export default function VictoryScreen({
  session,
  xpEarned,
  coinsEarned,
  newlyEarnedBadges,
  newlyUnlockedCosmetics,
  bossWon,
  progress,
  onContinue,
  onHome,
}: VictoryScreenProps) {
  const accuracy = session.questionsAnswered > 0 ? Math.round((session.correct / session.questionsAnswered) * 100) : 0;
  const stars = accuracy >= 90 ? 3 : accuracy >= 70 ? 2 : accuracy >= 40 ? 1 : 0;

  useEffect(() => {
    playSfx('victory');
  }, []);

  const level = getLevelFromXp(progress.xp);
  const leveledUp = getLevelFromXp(progress.xp - xpEarned) < level;

  // Recommend next quest
  const recommendation = (() => {
    if (session.mode === 'bossBattle' && !bossWon) return 'Try Mistake Rescue to strengthen tricky facts.';
    if (session.missedFacts.length > 0) return 'Mistake Rescue can help with the facts you missed.';
    if (session.factsMastered.length > 0) return 'Great mastery! Try a Boss Battle next.';
    return 'Keep your streak going with another Daily Quest tomorrow!';
  })();

  return (
    <div className="min-h-dvh flex flex-col items-center gap-6 px-4 py-8 max-w-xl mx-auto text-center pb-8">
      <KnightSprite state="victory" size="lg" />

      <div>
        <h1 className="font-display text-3xl font-extrabold text-knight-blue-dark">
          {session.mode === 'bossBattle' ? (bossWon ? 'Boss Defeated!' : 'Great Effort!') : 'Quest Complete!'}
        </h1>
        {leveledUp && (
          <p className="font-display text-lg font-bold text-amber-500 mt-1 animate-pulse-soft">
            🎉 Level Up! You reached Level {level}!
          </p>
        )}
      </div>

      <RewardChest xpEarned={xpEarned} coinsEarned={coinsEarned} starsEarned={stars} />

      <div className="grid grid-cols-2 gap-3 w-full">
        <div className="rounded-2xl bg-blue-50 border-2 border-blue-100 p-4">
          <div className="font-display text-2xl font-extrabold text-blue-700">
            {session.correct}/{session.questionsAnswered}
          </div>
          <div className="text-xs text-blue-500 font-semibold">Correct Answers</div>
        </div>
        <div className="rounded-2xl bg-green-50 border-2 border-green-100 p-4">
          <div className="font-display text-2xl font-extrabold text-green-700">{session.factsMastered.length}</div>
          <div className="text-xs text-green-500 font-semibold">Facts Mastered</div>
        </div>
      </div>

      {session.factsMastered.length > 0 && (
        <div className="w-full">
          <h3 className="font-display font-bold text-gray-700 mb-2">Newly Mastered Facts</h3>
          <div className="flex flex-wrap gap-2 justify-center">
            {session.factsMastered.map((key) => {
              const { a, b } = parseFactKey(key as FactKey);
              return (
                <span
                  key={key}
                  className="rounded-full bg-green-100 border border-green-300 text-green-700 text-sm font-bold px-3 py-1"
                >
                  {a} × {b} = {a * b}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {newlyEarnedBadges.length > 0 && (
        <div className="w-full">
          <h3 className="font-display font-bold text-gray-700 mb-2">New Badges!</h3>
          <div className="flex flex-wrap gap-2 justify-center">
            {newlyEarnedBadges.map((b) => (
              <span
                key={b.id}
                className="rounded-full bg-amber-50 border-2 border-amber-300 text-amber-700 text-sm font-bold px-3 py-2 animate-level-glow"
              >
                {b.icon} {b.name}
              </span>
            ))}
          </div>
        </div>
      )}

      {newlyUnlockedCosmetics.length > 0 && (
        <div className="w-full">
          <h3 className="font-display font-bold text-gray-700 mb-2">New Gear Unlocked!</h3>
          <div className="flex flex-wrap gap-2 justify-center">
            {newlyUnlockedCosmetics.map((c) => (
              <span
                key={c.id}
                className="rounded-full bg-purple-50 border-2 border-purple-300 text-purple-700 text-sm font-bold px-3 py-2"
              >
                {c.icon} {c.name}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-2xl bg-parchment border-2 border-amber-100 p-4 w-full">
        <p className="text-sm font-semibold text-amber-800">{recommendation}</p>
      </div>

      <div className="w-full flex flex-col gap-3">
        <button
          onClick={onContinue}
          className="w-full rounded-2xl bg-knight-blue text-white font-display text-lg font-extrabold py-4 shadow-md hover:bg-knight-blue-dark active:scale-95 transition-all"
        >
          Play Again
        </button>
        <button
          onClick={onHome}
          className="w-full rounded-2xl bg-white border-2 border-gray-200 font-display text-lg font-bold text-gray-700 py-4 shadow-sm hover:bg-gray-50 active:scale-95 transition-all"
        >
          Back to Castle
        </button>
      </div>
    </div>
  );
}
