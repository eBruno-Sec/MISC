import type { UserProgress } from '../types';
import ParentDashboard from '../components/ParentDashboard';
import { extendFacts } from '../lib/facts';

type ParentScreenProps = {
  progress: UserProgress;
  onUpdateProgress: (progress: UserProgress) => void;
  onReset: () => void;
  onBack: () => void;
};

export default function ParentScreen({ progress, onUpdateProgress, onReset, onBack }: ParentScreenProps) {
  function handleMaxFactorChange(value: 10 | 12) {
    onUpdateProgress({
      ...progress,
      maxFactor: value,
      facts: extendFacts(progress.facts, value),
      settings: { ...progress.settings, maxFactor: value },
    });
  }

  function handleSessionLengthChange(value: number) {
    onUpdateProgress({
      ...progress,
      settings: { ...progress.settings, sessionQuestionCount: value },
    });
  }

  function handleTimedModeToggle(value: boolean) {
    onUpdateProgress({
      ...progress,
      settings: { ...progress.settings, timedModeEnabled: value },
    });
  }

  return (
    <div className="flex flex-col gap-6 px-4 py-6 max-w-3xl mx-auto">
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="rounded-full bg-white border-2 border-gray-200 w-10 h-10 flex items-center justify-center text-xl shadow-sm hover:bg-gray-50"
          aria-label="Back to home"
        >
          ←
        </button>
        <h1 className="font-display text-2xl md:text-3xl font-extrabold text-knight-blue-dark">Parent Dashboard</h1>
      </div>

      <ParentDashboard
        progress={progress}
        onReset={onReset}
        onMaxFactorChange={handleMaxFactorChange}
        onSessionLengthChange={handleSessionLengthChange}
        onTimedModeToggle={handleTimedModeToggle}
      />
    </div>
  );
}
