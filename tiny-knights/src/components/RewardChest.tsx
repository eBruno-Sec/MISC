import { useEffect, useState } from 'react';

type RewardChestProps = {
  xpEarned: number;
  coinsEarned: number;
  starsEarned: number;
};

export default function RewardChest({ xpEarned, coinsEarned, starsEarned }: RewardChestProps) {
  const [opened, setOpened] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setOpened(true), 300);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="flex flex-col items-center gap-4">
      <div className={`text-7xl transition-transform duration-500 ${opened ? 'animate-level-glow scale-110' : ''}`}>
        {opened ? '📦✨' : '📦'}
      </div>

      {opened && (
        <div className="flex flex-wrap items-center justify-center gap-3">
          <div className="flex items-center gap-1 bg-gold/30 rounded-full px-4 py-2 font-bold text-amber-700">
            <span className="text-xl">⚡</span> +{xpEarned} XP
          </div>
          <div className="flex items-center gap-1 bg-coin/20 rounded-full px-4 py-2 font-bold text-amber-700">
            <span className="text-xl">🪙</span> +{coinsEarned}
          </div>
          <div className="flex items-center gap-1 bg-yellow-100 rounded-full px-4 py-2 font-bold text-amber-700">
            {Array.from({ length: 3 }).map((_, i) => (
              <span
                key={i}
                className={i < starsEarned ? 'animate-victory-star' : 'opacity-30'}
                style={{ animationDelay: `${i * 120}ms` }}
              >
                ⭐
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
