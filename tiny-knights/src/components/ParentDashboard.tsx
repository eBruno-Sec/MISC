import type { UserProgress } from '../types';
import { getOverallMasteryPercent, parseFactKey } from '../lib/facts';
import { getMasteryLabel } from '../lib/mastery';
import { getQuestName } from '../lib/rewards';

type ParentDashboardProps = {
  progress: UserProgress;
  onReset: () => void;
  onMaxFactorChange: (value: 10 | 12) => void;
  onSessionLengthChange: (value: number) => void;
  onTimedModeToggle: (value: boolean) => void;
};

export default function ParentDashboard({
  progress,
  onReset,
  onMaxFactorChange,
  onSessionLengthChange,
  onTimedModeToggle,
}: ParentDashboardProps) {
  const facts = Object.values(progress.facts);
  const masteredCount = facts.filter((f) => f.isMastered).length;
  const overallPercent = getOverallMasteryPercent(progress.facts);

  const weakFacts = facts
    .filter((f) => !f.isMastered && f.attempts > 0)
    .sort((a, b) => a.masteryLevel - b.masteryLevel || b.incorrect - a.incorrect)
    .slice(0, 8);

  const slowFacts = facts
    .filter((f) => f.averageResponseMs !== null && !f.isMastered)
    .sort((a, b) => (b.averageResponseMs ?? 0) - (a.averageResponseMs ?? 0))
    .slice(0, 5);

  const recentSessions = [...progress.sessions]
    .sort((a, b) => new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime())
    .slice(0, 5);

  // Recommend the table with the lowest average mastery among unmastered facts
  const tableAverages: { table: number; avg: number }[] = [];
  for (let t = 1; t <= progress.maxFactor; t++) {
    const tableFacts = facts.filter((f) => f.a === t || f.b === t);
    const unmastered = tableFacts.filter((f) => !f.isMastered);
    if (unmastered.length === 0) continue;
    const avg = unmastered.reduce((sum, f) => sum + f.masteryLevel, 0) / unmastered.length;
    tableAverages.push({ table: t, avg });
  }
  tableAverages.sort((a, b) => a.avg - b.avg);
  const recommendedTable = tableAverages[0]?.table ?? null;

  function handleReset() {
    if (window.confirm('Reset all progress? This cannot be undone.')) {
      onReset();
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Overall Mastery" value={`${overallPercent}%`} icon="🎯" />
        <StatCard label="Facts Mastered" value={`${masteredCount}/${facts.length}`} icon="🏆" />
        <StatCard label="Daily Streak" value={`${progress.dailyStreak} days`} icon="🔥" />
        <StatCard
          label="Recommended Focus"
          value={recommendedTable ? `${recommendedTable}× Table` : 'All mastered!'}
          icon="🧭"
        />
      </div>

      {/* Weak facts */}
      <section>
        <h3 className="font-display text-lg font-bold text-gray-700 mb-2">Facts Needing Practice</h3>
        {weakFacts.length === 0 ? (
          <p className="text-sm text-gray-500">No struggling facts right now. Great progress!</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {weakFacts.map((f) => {
              const { a, b } = parseFactKey(f.key);
              return (
                <span
                  key={f.key}
                  className="rounded-full bg-red-50 border border-red-200 text-red-700 text-sm font-bold px-3 py-1"
                >
                  {a} × {b} <span className="text-red-400 font-normal">({getMasteryLabel(f.masteryLevel)})</span>
                </span>
              );
            })}
          </div>
        )}
      </section>

      {/* Slow facts */}
      <section>
        <h3 className="font-display text-lg font-bold text-gray-700 mb-2">Slower Response Facts</h3>
        {slowFacts.length === 0 ? (
          <p className="text-sm text-gray-500">No timing data yet.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {slowFacts.map((f) => {
              const { a, b } = parseFactKey(f.key);
              return (
                <span
                  key={f.key}
                  className="rounded-full bg-amber-50 border border-amber-200 text-amber-700 text-sm font-bold px-3 py-1"
                >
                  {a} × {b} ~ {Math.round((f.averageResponseMs ?? 0) / 100) / 10}s
                </span>
              );
            })}
          </div>
        )}
      </section>

      {/* Recent sessions */}
      <section>
        <h3 className="font-display text-lg font-bold text-gray-700 mb-2">Recent Sessions</h3>
        {recentSessions.length === 0 ? (
          <p className="text-sm text-gray-500">No sessions yet.</p>
        ) : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b">
                  <th className="py-2 pr-4">Date</th>
                  <th className="py-2 pr-4">Mode</th>
                  <th className="py-2 pr-4">Correct</th>
                  <th className="py-2 pr-4">Total</th>
                  <th className="py-2 pr-4">Mastered</th>
                </tr>
              </thead>
              <tbody>
                {recentSessions.map((s) => (
                  <tr key={s.id} className="border-b last:border-0">
                    <td className="py-2 pr-4 whitespace-nowrap">
                      {new Date(s.startedAt).toLocaleDateString()}
                    </td>
                    <td className="py-2 pr-4 capitalize whitespace-nowrap">
                      {s.mode.replace(/([A-Z])/g, ' $1')}
                    </td>
                    <td className="py-2 pr-4">{s.correct}</td>
                    <td className="py-2 pr-4">{s.questionsAnswered}</td>
                    <td className="py-2 pr-4">{s.factsMastered.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Quest completions */}
      <section>
        <h3 className="font-display text-lg font-bold text-gray-700 mb-2">Quest Completions</h3>
        {Object.keys(progress.questCompletions).length === 0 ? (
          <p className="text-sm text-gray-500">No quests completed yet.</p>
        ) : (
          <div className="overflow-x-auto scrollbar-thin">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b">
                  <th className="py-2 pr-4">Quest</th>
                  <th className="py-2 pr-4">Times</th>
                  <th className="py-2 pr-4">Best Accuracy</th>
                  <th className="py-2 pr-4">Stars</th>
                  <th className="py-2 pr-4">Last Completed</th>
                </tr>
              </thead>
              <tbody>
                {Object.values(progress.questCompletions)
                  .sort((a, b) => new Date(b.lastCompletedAt).getTime() - new Date(a.lastCompletedAt).getTime())
                  .map((q) => (
                    <tr key={q.questId} className="border-b last:border-0">
                      <td className="py-2 pr-4 whitespace-nowrap">{getQuestName(q.mode, q.table, q.bossId)}</td>
                      <td className="py-2 pr-4">{q.timesCompleted}x</td>
                      <td className="py-2 pr-4">{q.bestAccuracy}%</td>
                      <td className="py-2 pr-4">
                        {'⭐'.repeat(q.starsEarned)}
                        {'☆'.repeat(3 - q.starsEarned)}
                      </td>
                      <td className="py-2 pr-4 whitespace-nowrap">
                        {new Date(q.lastCompletedAt).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Settings */}
      <section className="rounded-2xl bg-parchment border-2 border-amber-100 p-4 flex flex-col gap-4">
        <h3 className="font-display text-lg font-bold text-gray-700">Settings</h3>

        <div className="flex items-center justify-between gap-4">
          <label htmlFor="maxFactor" className="text-sm font-semibold text-gray-700">
            Table Range
          </label>
          <select
            id="maxFactor"
            value={progress.maxFactor}
            onChange={(e) => onMaxFactorChange(Number(e.target.value) as 10 | 12)}
            className="rounded-xl border-2 border-gray-200 px-3 py-2 text-sm font-bold bg-white"
          >
            <option value={10}>1-10 (Easy)</option>
            <option value={12}>1-12 (Advanced)</option>
          </select>
        </div>

        <div className="flex items-center justify-between gap-4">
          <label htmlFor="sessionLength" className="text-sm font-semibold text-gray-700">
            Session Length
          </label>
          <select
            id="sessionLength"
            value={progress.settings.sessionQuestionCount}
            onChange={(e) => onSessionLengthChange(Number(e.target.value))}
            className="rounded-xl border-2 border-gray-200 px-3 py-2 text-sm font-bold bg-white"
          >
            <option value={10}>10 questions</option>
            <option value={12}>12 questions</option>
            <option value={20}>20 questions</option>
            <option value={30}>30 questions</option>
            <option value={40}>40 questions</option>
          </select>
        </div>

        <div className="flex items-center justify-between gap-4">
          <label htmlFor="timedMode" className="text-sm font-semibold text-gray-700">
            Timed Mode (Speed Round)
          </label>
          <button
            id="timedMode"
            role="switch"
            aria-checked={progress.settings.timedModeEnabled}
            onClick={() => onTimedModeToggle(!progress.settings.timedModeEnabled)}
            className={`relative w-14 h-8 rounded-full transition-colors ${
              progress.settings.timedModeEnabled ? 'bg-hp-green' : 'bg-gray-300'
            }`}
          >
            <span
              className={`absolute top-1 left-1 w-6 h-6 rounded-full bg-white shadow transition-transform ${
                progress.settings.timedModeEnabled ? 'translate-x-6' : ''
              }`}
            />
          </button>
        </div>

        <button
          onClick={handleReset}
          className="mt-2 self-start rounded-xl bg-red-50 border-2 border-red-200 text-red-600 font-bold text-sm px-4 py-2 hover:bg-red-100 transition-colors"
        >
          Reset All Progress
        </button>
      </section>
    </div>
  );
}

function StatCard({ label, value, icon }: { label: string; value: string; icon: string }) {
  return (
    <div className="rounded-2xl bg-white border-2 border-gray-100 p-4 flex flex-col gap-1 shadow-sm">
      <div className="text-2xl" aria-hidden="true">
        {icon}
      </div>
      <div className="font-display text-xl md:text-2xl font-extrabold text-gray-800">{value}</div>
      <div className="text-xs text-gray-500 font-semibold">{label}</div>
    </div>
  );
}
