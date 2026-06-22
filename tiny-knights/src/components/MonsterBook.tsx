import type { MonsterBookEntry } from '../types';
import { MONSTERS, BOSSES } from '../data/monsters';

type MonsterBookProps = {
  entries: MonsterBookEntry[];
  maxFactor?: number;
};

export default function MonsterBook({ entries, maxFactor = 12 }: MonsterBookProps) {
  const entryMap = new Map(entries.map((e) => [e.monsterId, e]));
  const monsters = MONSTERS.filter((m) => m.id !== 'finalboss');
  const bosses = BOSSES.filter((b) => (b.unlockTable ?? 0) <= maxFactor);

  return (
    <div className="flex flex-col gap-5">
      <div>
        <h4 className="font-display text-sm font-bold text-gray-600 mb-2">Monsters</h4>
        <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-3">
          {monsters.map((monster) => {
            const entry = entryMap.get(monster.id);
            const discovered = !!entry;

            return (
              <div
                key={monster.id}
                className={`flex flex-col items-center gap-1 rounded-2xl border-2 p-3 text-center ${
                  discovered ? 'bg-white border-gray-200' : 'bg-gray-100 border-gray-200'
                }`}
              >
                <span className={`text-3xl ${discovered ? '' : 'opacity-20 grayscale'}`} aria-hidden="true">
                  {monster.emoji}
                </span>
                <span className={`text-xs font-bold ${discovered ? 'text-gray-700' : 'text-gray-400'}`}>
                  {discovered ? monster.name : '???'}
                </span>
                {discovered && (
                  <span className="text-[10px] text-gray-500">Defeated ×{entry.defeats}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h4 className="font-display text-sm font-bold text-gray-600 mb-2">Bosses</h4>
        <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-6 gap-3">
          {bosses.map((boss) => {
            const entry = entryMap.get(boss.id);
            const discovered = !!entry;

            return (
              <div
                key={boss.id}
                className={`flex flex-col items-center gap-1 rounded-2xl border-2 p-3 text-center ${
                  discovered ? 'bg-amber-50 border-amber-200' : 'bg-gray-100 border-gray-200'
                }`}
              >
                <span className={`text-3xl ${discovered ? '' : 'opacity-20 grayscale'}`} aria-hidden="true">
                  {boss.emoji}
                </span>
                <span className={`text-xs font-bold ${discovered ? 'text-gray-700' : 'text-gray-400'}`}>
                  {discovered ? boss.name : '???'}
                </span>
                {discovered && (
                  <span className="text-[10px] text-gray-500">Defeated ×{entry.defeats}</span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
