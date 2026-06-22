import { useEffect, useState } from 'react';
import type { Monster } from '../types';

export type MonsterAnimState = 'idle' | 'hurt' | 'defeated';

type MonsterSpriteProps = {
  monster: Monster;
  state: MonsterAnimState;
  size?: 'sm' | 'md' | 'lg';
};

const sizeMap = {
  sm: 'text-5xl',
  md: 'text-7xl',
  lg: 'text-8xl md:text-9xl landscape:text-6xl',
};

export default function MonsterSprite({ monster, state, size = 'lg' }: MonsterSpriteProps) {
  const [localState, setLocalState] = useState<MonsterAnimState>('idle');

  useEffect(() => {
    if (state === 'idle') {
      setLocalState('idle');
      return;
    }
    setLocalState(state);
    if (state === 'hurt') {
      const timer = setTimeout(() => setLocalState('idle'), 450);
      return () => clearTimeout(timer);
    }
  }, [state]);

  if (localState === 'defeated') {
    return (
      <div className="relative flex items-center justify-center" aria-label={`${monster.name} defeated`}>
        <div className={`${sizeMap[size]} animate-poof`} aria-hidden="true">
          {monster.emoji}
        </div>
        <div className="absolute flex gap-2 text-3xl">
          <span className="animate-coin-pop" style={{ animationDelay: '0ms' }}>🪙</span>
          <span className="animate-coin-pop" style={{ animationDelay: '100ms' }}>🪙</span>
          <span className="animate-coin-pop" style={{ animationDelay: '200ms' }}>🪙</span>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`${sizeMap[size]} leading-none select-none ${
        localState === 'idle' ? 'animate-bounce-idle' : ''
      } ${localState === 'hurt' ? 'animate-damage-shake' : ''}`}
      aria-label={`${monster.name}, a friendly cartoon monster`}
    >
      <span className="drop-shadow-md">{monster.emoji}</span>
    </div>
  );
}
