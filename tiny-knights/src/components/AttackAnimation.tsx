import { useEffect, useState } from 'react';

type AttackAnimationProps = {
  trigger: number;
  type: 'attack' | 'block';
};

/**
 * Renders a brief full-arena flash/particle effect on top of the battle scene.
 * `trigger` should be incremented each time an animation should fire.
 */
export default function AttackAnimation({ trigger, type }: AttackAnimationProps) {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (trigger === 0) return;
    setVisible(true);
    const timer = setTimeout(() => setVisible(false), 450);
    return () => clearTimeout(timer);
  }, [trigger]);

  if (!visible) return null;

  return (
    <div className="absolute inset-0 pointer-events-none flex items-center justify-center z-20" aria-hidden="true">
      {type === 'attack' ? (
        <div className="text-6xl animate-victory-star">💥</div>
      ) : (
        <div className="text-6xl animate-shield-block">✨</div>
      )}
    </div>
  );
}
