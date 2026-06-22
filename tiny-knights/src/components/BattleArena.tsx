import type { Monster } from '../types';
import KnightSprite, { type KnightState } from './KnightSprite';
import MonsterSprite, { type MonsterAnimState } from './MonsterSprite';
import ProgressBar from './ProgressBar';
import AttackAnimation from './AttackAnimation';

type BattleArenaProps = {
  monster: Monster;
  monsterHp: number;
  monsterMaxHp: number;
  knightEnergy: number;
  knightMaxEnergy: number;
  knightState: KnightState;
  monsterState: MonsterAnimState;
  attackTrigger: number;
  blockTrigger: number;
  worldName: string;
  worldEmoji: string;
};

export default function BattleArena({
  monster,
  monsterHp,
  monsterMaxHp,
  knightEnergy,
  knightMaxEnergy,
  knightState,
  monsterState,
  attackTrigger,
  blockTrigger,
  worldName,
  worldEmoji,
}: BattleArenaProps) {
  return (
    <div className="relative rounded-3xl bg-gradient-to-b from-sky-200 via-sky-100 to-meadow/40 border-4 border-white shadow-lg overflow-hidden">
      <AttackAnimation trigger={attackTrigger} type="attack" />
      <AttackAnimation trigger={blockTrigger} type="block" />

      {/* World label */}
      <div className="absolute top-3 left-3 flex items-center gap-1 bg-white/80 rounded-full px-3 py-1 text-xs md:text-sm font-bold text-gray-700 shadow-sm z-10">
        <span aria-hidden="true">{worldEmoji}</span>
        <span>{worldName}</span>
      </div>

      {/* Ground decoration */}
      <div className="absolute bottom-0 left-0 right-0 h-10 md:h-14 bg-meadow/70" aria-hidden="true" />
      <div className="absolute bottom-8 left-4 text-2xl opacity-60" aria-hidden="true">🌸</div>
      <div className="absolute bottom-9 right-6 text-2xl opacity-60" aria-hidden="true">🌼</div>
      <div className="absolute bottom-8 left-1/2 text-xl opacity-40" aria-hidden="true">☁️</div>

      <div className="relative grid grid-cols-2 gap-4 px-6 pt-10 pb-6 md:px-12 md:pt-14 md:pb-10 landscape:pt-8 landscape:pb-4 landscape:px-4">
        {/* Knight side */}
        <div className="flex flex-col items-center gap-2 landscape:gap-1">
          <KnightSprite state={knightState} size="lg" />
          <div className="w-full max-w-[140px] md:max-w-[180px]">
            <ProgressBar current={knightEnergy} max={knightMaxEnergy} label="Knight" colorClass="bg-knight-blue" />
          </div>
        </div>

        {/* Monster side */}
        <div className="flex flex-col items-center gap-2 landscape:gap-1">
          <MonsterSprite monster={monster} state={monsterState} size="lg" />
          <div className="w-full max-w-[140px] md:max-w-[180px]">
            <ProgressBar current={monsterHp} max={monsterMaxHp} label={monster.name} />
          </div>
        </div>
      </div>
    </div>
  );
}
