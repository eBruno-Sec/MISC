import type { FactKey, FactState, QuestCompletion } from '../types';
import { WORLDS } from '../data/worlds';
import { isTableMastered } from '../lib/facts';

type QuestMapProps = {
  facts: Record<FactKey, FactState>;
  maxFactor: number;
  questCompletions: Record<string, QuestCompletion>;
  onSelectTable: (table: number) => void;
};

export default function QuestMap({ facts, maxFactor, questCompletions, onSelectTable }: QuestMapProps) {
  const worlds = WORLDS.filter((w) => w.table !== null && w.table <= maxFactor);

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
      {worlds.map((world) => {
        const table = world.table as number;
        const mastered = isTableMastered(facts, table, maxFactor);
        const completion = questCompletions[`tableTrainer-${table}`];

        return (
          <button
            key={world.id}
            onClick={() => onSelectTable(table)}
            className={`relative flex flex-col items-center gap-2 rounded-2xl border-2 p-4 shadow-sm transition-all active:scale-95 hover:-translate-y-0.5 ${
              mastered
                ? 'bg-green-50 border-green-300'
                : 'bg-white border-gray-200 hover:border-knight-blue/40'
            }`}
          >
            {mastered && (
              <span className="absolute top-1 right-1 text-lg" aria-label="Mastered">
                ✅
              </span>
            )}
            <span className="text-3xl md:text-4xl" aria-hidden="true">
              {world.emoji}
            </span>
            <span className="font-display font-bold text-sm md:text-base text-gray-700 text-center">
              {world.name}
            </span>
            <span className="text-xs text-gray-500">Table of {table}</span>
            {completion && (
              <div className="flex items-center gap-1 mt-1">
                <span className="text-xs" aria-label={`${completion.starsEarned} stars`}>
                  {'⭐'.repeat(completion.starsEarned)}
                  {'☆'.repeat(3 - completion.starsEarned)}
                </span>
                <span className="text-[10px] font-bold text-gray-400">
                  Completed {completion.timesCompleted}x
                </span>
              </div>
            )}
          </button>
        );
      })}
    </div>
  );
}
