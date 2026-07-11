import type { UserProgress } from '../types';
import QuestMap from '../components/QuestMap';

type ModeSelectScreenProps = {
  progress: UserProgress;
  onSelectTableTrainer: (table: number) => void;
  onSelectBossBattle: () => void;
  onSelectMistakeRescue: () => void;
  onSelectSpeedRound: () => void;
  onBack: () => void;
};

export default function ModeSelectScreen({
  progress,
  onSelectTableTrainer,
  onSelectBossBattle,
  onSelectMistakeRescue,
  onSelectSpeedRound,
  onBack,
}: ModeSelectScreenProps) {
  const missedFactsCount = Object.values(progress.facts).filter((f) => f.incorrect > 0 && !f.isMastered).length;
  const bossCompletions = Object.values(progress.questCompletions).filter((q) => q.mode === 'bossBattle');
  const bossCompletion =
    bossCompletions.length > 0
      ? {
          timesCompleted: bossCompletions.reduce((sum, q) => sum + q.timesCompleted, 0),
          starsEarned: Math.max(...bossCompletions.map((q) => q.starsEarned)),
        }
      : undefined;
  const mistakeCompletion = progress.questCompletions['mistakeRescue'];
  const speedCompletion = progress.questCompletions['speedRound'];

  return (
    <div className="min-h-dvh flex flex-col gap-6 px-4 py-6 max-w-3xl mx-auto pb-8">
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="rounded-full bg-white border-2 border-gray-200 w-10 h-10 flex items-center justify-center text-xl text-gray-700 shadow-sm hover:bg-gray-50"
          aria-label="Back to home"
        >
          ←
        </button>
        <h1 className="font-display text-2xl md:text-3xl font-extrabold text-knight-blue-dark">Quest Modes</h1>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <button
          onClick={onSelectBossBattle}
          className="rounded-2xl bg-gradient-to-br from-red-50 to-orange-50 border-2 border-red-200 p-5 text-left shadow-sm hover:-translate-y-0.5 transition-all active:scale-95"
        >
          <div className="text-3xl mb-2" aria-hidden="true">🐲</div>
          <h3 className="font-display font-bold text-lg text-gray-800">Boss Battle</h3>
          <p className="text-sm text-gray-500">Take on a tough boss with your trickiest facts.</p>
          <CompletionBadge completion={bossCompletion} />
        </button>

        <button
          onClick={onSelectMistakeRescue}
          className="rounded-2xl bg-gradient-to-br from-blue-50 to-cyan-50 border-2 border-blue-200 p-5 text-left shadow-sm hover:-translate-y-0.5 transition-all active:scale-95"
        >
          <div className="text-3xl mb-2" aria-hidden="true">🧡</div>
          <h3 className="font-display font-bold text-lg text-gray-800">Mistake Rescue</h3>
          <p className="text-sm text-gray-500">
            {missedFactsCount > 0
              ? `${missedFactsCount} facts to practice gently, no timer.`
              : 'Calm practice with extra hints, no timer.'}
          </p>
          <CompletionBadge completion={mistakeCompletion} />
        </button>

        <button
          onClick={onSelectSpeedRound}
          className="rounded-2xl bg-gradient-to-br from-yellow-50 to-amber-50 border-2 border-yellow-200 p-5 text-left shadow-sm hover:-translate-y-0.5 transition-all active:scale-95"
        >
          <div className="text-3xl mb-2" aria-hidden="true">⏱️</div>
          <h3 className="font-display font-bold text-lg text-gray-800">Speed Round</h3>
          <p className="text-sm text-gray-500">60 seconds. Beat your personal best!</p>
          <CompletionBadge completion={speedCompletion} />
        </button>
      </div>

      <div>
        <h2 className="font-display text-xl font-bold text-gray-700 mb-3">Table Trainer</h2>
        <p className="text-sm text-gray-500 mb-3">Pick a world to focus on one times table.</p>
        <QuestMap
          facts={progress.facts}
          maxFactor={progress.maxFactor}
          questCompletions={progress.questCompletions}
          onSelectTable={onSelectTableTrainer}
        />
      </div>
    </div>
  );
}

function CompletionBadge({ completion }: { completion?: { timesCompleted: number; starsEarned: number } }) {
  if (!completion) return null;
  return (
    <div className="flex items-center gap-1 mt-2">
      <span className="text-sm" aria-label={`${completion.starsEarned} stars`}>
        {'⭐'.repeat(completion.starsEarned)}
        {'☆'.repeat(3 - completion.starsEarned)}
      </span>
      <span className="text-xs font-bold text-gray-400">Completed {completion.timesCompleted}x</span>
    </div>
  );
}
