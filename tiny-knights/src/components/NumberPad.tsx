type NumberPadProps = {
  value: string;
  onDigit: (digit: string) => void;
  onBackspace: () => void;
  onSubmit: () => void;
  disabled?: boolean;
};

export default function NumberPad({ value, onDigit, onBackspace, onSubmit, disabled }: NumberPadProps) {
  const digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '⌫', '0', '✓'];

  return (
    <div className="w-full max-w-xs mx-auto">
      <div
        className="mb-3 h-16 md:h-20 flex items-center justify-center rounded-2xl bg-white border-4 border-knight-blue/30 font-display text-4xl md:text-5xl font-extrabold text-knight-blue-dark tabular-nums shadow-inner"
        aria-live="polite"
        aria-label={`Your answer: ${value || 'empty'}`}
      >
        {value || <span className="text-gray-300">_</span>}
      </div>

      <div className="grid grid-cols-3 gap-2 md:gap-3">
        {digits.map((d) => {
          const handleClick = () => {
            if (disabled) return;
            if (d === '⌫') onBackspace();
            else if (d === '✓') onSubmit();
            else onDigit(d);
          };

          return (
            <button
              key={d}
              onClick={handleClick}
              disabled={disabled}
              aria-label={d === '⌫' ? 'Delete' : d === '✓' ? 'Submit answer' : `Number ${d}`}
              className={`h-14 md:h-16 rounded-2xl font-display text-2xl md:text-3xl font-bold shadow-sm active:scale-95 transition-all disabled:opacity-50 ${
                d === '✓'
                  ? 'bg-hp-green text-white hover:bg-green-500'
                  : d === '⌫'
                  ? 'bg-gray-200 text-gray-600 hover:bg-gray-300'
                  : 'bg-white text-knight-blue-dark border-2 border-knight-blue/20 hover:bg-knight-blue/10'
              }`}
            >
              {d}
            </button>
          );
        })}
      </div>
    </div>
  );
}
