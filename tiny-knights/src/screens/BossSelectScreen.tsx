import type { UserProgress } from '../types';
import { getBosses } from '../data/monsters';
import { getMonsterMaxHp } from '../lib/battleEngine';

type BossSelectScreenProps = {
  progress: UserProgress;
  onSelectBoss: (bossId: string) => void;
  onBack: () => void;
};

const difficultyColors: Record<string, string> = {
  Easy: 'bg-green-50 border-green-200 text-green-700',
  Medium: 'bg-amber-50 border-amber-200 text-amber-700',
  Hard: 'bg-red-50 border-red-200 text-red-700',
  Champion: 'bg-purple-50 border-purple-200 text-purple-700',
};

export default function BossSelectScreen({ progress, onSelectBoss, onBack }: BossSelectScreenProps) {
  const bosses = getBosses(progress.maxFactor);
  const entryMap = new Map(progress.monsterBook.map((e) => [e.monsterId, e]));

  return (
    <div className="flex flex-col gap-6 px-4 py-6 max-w-3xl mx-auto">
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="rounded-full bg-white border-2 border-gray-200 w-10 h-10 flex items-center justify-center text-xl shadow-sm hover:bg-gray-50"
          aria-label="Back to quest modes"
        >
          ←
        </button>
        <h1 className="font-display text-2xl md:text-3xl font-extrabold text-knight-blue-dark">Choose Your Boss</h1>
      </div>

      <p className="text-sm text-gray-500">
        Each boss tests a different range of times tables. Defeat them to log them in your Monster Book.
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {bosses.map((boss) => {
          const hp = getMonsterMaxHp(boss, 'bossBattle');
          const entry = entryMap.get(boss.id);
          const defeats = entry?.defeats ?? 0;
          const difficultyClass = difficultyColors[boss.difficultyLabel ?? 'Easy'];

          return (
            <button
              key={boss.id}
              onClick={() => onSelectBoss(boss.id)}
              className="relative flex flex-col gap-2 rounded-2xl bg-white border-2 border-gray-200 p-5 text-left shadow-sm hover:-translate-y-0.5 hover:border-knight-blue/40 transition-all active:scale-95"
            >
              <div className="flex items-center gap-3">
                <span className="text-4xl" aria-hidden="true">{boss.emoji}</span>
                <div className="flex flex-col">
                  <span className="font-display font-bold text-lg text-gray-800">{boss.name}</span>
                  <span className={`inline-block self-start mt-1 rounded-full border px-2 py-0.5 text-[10px] font-bold ${difficultyClass}`}>
                    {boss.difficultyLabel}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between text-sm text-gray-500 mt-1">
                <span>❤️ {hp} HP</span>
                <span>Defeated ×{defeats}</span>
              </div>

              <p className="text-xs text-gray-400">
                Tables up to ×{boss.table === 0 ? progress.maxFactor : boss.table}
              </p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
