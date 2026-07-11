import { useEffect, useState } from 'react';
import knightAvatar from '../assets/knight-avatar.png';

export type KnightState = 'idle' | 'attack' | 'block' | 'victory' | 'hurt';

type KnightSpriteProps = {
  state: KnightState;
  size?: 'sm' | 'md' | 'lg';
};

const sizeMap = {
  sm: 'w-16 h-auto md:w-20 landscape:w-14',
  md: 'w-28 h-auto md:w-36 landscape:w-24',
  lg: 'w-36 h-auto md:w-48 landscape:w-28',
};

export default function KnightSprite({ state, size = 'lg' }: KnightSpriteProps) {
  const [localState, setLocalState] = useState<KnightState>(state);
  const [prevState, setPrevState] = useState(state);

  // Adjust state during render when the prop changes (avoids an effect round-trip)
  if (state !== prevState) {
    setPrevState(state);
    setLocalState(state);
  }

  useEffect(() => {
    if (localState === 'idle') return;
    const timer = setTimeout(() => setLocalState('idle'), 500);
    return () => clearTimeout(timer);
  }, [localState]);

  const isAttacking = localState === 'attack';
  const isBlocking = localState === 'block';
  const isVictory = localState === 'victory';
  const isHurt = localState === 'hurt';

  return (
    <div className="relative flex items-end justify-center select-none" aria-label={`Knight is ${localState}`}>
      {/* Slash effect */}
      {isAttacking && (
        <div className="absolute -right-4 top-1/3 text-5xl md:text-6xl animate-slash z-10" aria-hidden="true">
          💥
        </div>
      )}

      {/* Shield block flash effect */}
      {isBlocking && (
        <div
          className="absolute -left-2 top-1/3 text-4xl md:text-5xl animate-shield-block z-10"
          aria-hidden="true"
        >
          🛡️
        </div>
      )}

      <img
        src={knightAvatar}
        alt="Tiny Knight"
        className={`${sizeMap[size]} drop-shadow-md ${
          localState === 'idle' ? 'animate-bounce-idle' : ''
        } ${isHurt ? 'animate-damage-shake' : ''} ${isVictory ? 'animate-victory-star' : ''}`}
      />

      {isVictory && (
        <div className="absolute -top-6 left-1/2 -translate-x-1/2 flex gap-1 text-2xl">
          <span className="animate-victory-star" style={{ animationDelay: '0ms' }}>⭐</span>
          <span className="animate-victory-star" style={{ animationDelay: '100ms' }}>✨</span>
          <span className="animate-victory-star" style={{ animationDelay: '200ms' }}>⭐</span>
        </div>
      )}
    </div>
  );
}
