type HpBarProps = {
  current: number;
  max: number;
  label: string;
  colorClass?: string;
};

export default function ProgressBar({ current, max, label, colorClass = 'bg-hp-green' }: HpBarProps) {
  const pct = max > 0 ? Math.max(0, Math.min(100, (current / max) * 100)) : 0;

  let barColor = colorClass;
  if (colorClass === 'bg-hp-green') {
    if (pct <= 30) barColor = 'bg-hp-red';
    else if (pct <= 60) barColor = 'bg-hp-yellow';
  }

  return (
    <div className="w-full">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs md:text-sm font-bold text-gray-700">{label}</span>
        <span className="text-xs md:text-sm font-semibold text-gray-500">
          {current}/{max}
        </span>
      </div>
      <div
        className="h-3 md:h-4 w-full rounded-full bg-gray-200 overflow-hidden border border-gray-300"
        role="progressbar"
        aria-valuenow={current}
        aria-valuemin={0}
        aria-valuemax={max}
        aria-label={label}
      >
        <div
          className={`h-full ${barColor} transition-all duration-300 ease-out rounded-full`}
          style={{ width: `${pct}%` }}
        />
      </div>
    </div>
  );
}
