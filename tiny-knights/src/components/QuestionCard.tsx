import type { QuestionType } from '../types';

type QuestionCardProps = {
  a: number;
  b: number;
  questionType: QuestionType;
  hiddenSlot?: 'a' | 'b' | 'product';
  multipleChoiceOptions?: number[];
  onChoiceSelect?: (value: number) => void;
};

export default function QuestionCard({
  a,
  b,
  questionType,
  hiddenSlot,
  multipleChoiceOptions,
  onChoiceSelect,
}: QuestionCardProps) {
  function renderEquation() {
    if (questionType === 'missingFactor' && hiddenSlot === 'a') {
      return (
        <>
          <span className="text-amber-500">?</span>
          <span className="mx-2">×</span>
          <span>{b}</span>
          <span className="mx-2">=</span>
          <span>{a * b}</span>
        </>
      );
    }
    if (questionType === 'missingFactor' && hiddenSlot === 'b') {
      return (
        <>
          <span>{a}</span>
          <span className="mx-2">×</span>
          <span className="text-amber-500">?</span>
          <span className="mx-2">=</span>
          <span>{a * b}</span>
        </>
      );
    }
    return (
      <>
        <span>{a}</span>
        <span className="mx-2">×</span>
        <span>{b}</span>
        <span className="mx-2">=</span>
        <span className="text-amber-500">?</span>
      </>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4">
      <div
        className="font-display text-4xl md:text-6xl font-extrabold text-gray-800 tracking-wide tabular-nums"
        aria-live="polite"
      >
        {renderEquation()}
      </div>

      {questionType === 'multipleChoice' && multipleChoiceOptions && (
        <div className="grid grid-cols-2 gap-3 w-full max-w-xs mt-2">
          {multipleChoiceOptions.map((opt) => (
            <button
              key={opt}
              onClick={() => onChoiceSelect?.(opt)}
              className="rounded-2xl bg-white border-2 border-knight-blue text-knight-blue font-display text-2xl md:text-3xl font-bold py-4 shadow-sm hover:bg-knight-blue hover:text-white active:scale-95 transition-all"
            >
              {opt}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
