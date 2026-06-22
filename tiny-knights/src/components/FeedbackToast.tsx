import type { FeedbackKind } from '../types';

type FeedbackToastProps = {
  message: string;
  kind: FeedbackKind;
  visible: boolean;
};

const kindStyles: Record<FeedbackKind, string> = {
  correct: 'bg-hp-green/90 text-white border-green-600',
  slow: 'bg-amber-400/90 text-amber-900 border-amber-500',
  incorrect: 'bg-sky-100 text-sky-900 border-sky-300',
  hint: 'bg-amber-50 text-amber-800 border-amber-200',
};

const kindIcons: Record<FeedbackKind, string> = {
  correct: '✅',
  slow: '⏱️',
  incorrect: '💡',
  hint: '💡',
};

export default function FeedbackToast({ message, kind, visible }: FeedbackToastProps) {
  if (!visible) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className={`w-full rounded-2xl border-2 px-4 py-3 text-center font-bold text-sm md:text-base shadow-sm transition-opacity ${kindStyles[kind]}`}
    >
      <span className="mr-2" aria-hidden="true">
        {kindIcons[kind]}
      </span>
      {message}
    </div>
  );
}
