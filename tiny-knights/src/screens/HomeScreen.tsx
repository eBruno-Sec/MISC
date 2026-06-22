import type { UserProgress } from '../types';
import { getLevelFromXp, getXpIntoLevel } from '../lib/rewards';
import KnightSprite from '../components/KnightSprite';
import ProgressBar from '../components/ProgressBar';

type HomeScreenProps = {
  progress: UserProgress;
  onStartDailyQuest: () => void;
  onNavigate: (screen: 'modeSelect' | 'parent' | 'settings') => void;
};

export default function HomeScreen({ progress, onStartDailyQuest, onNavigate }: HomeScreenProps) {
  const level = getLevelFromXp(progress.xp);
  const { current, needed } = getXpIntoLevel(progress.xp);

  return (
    <div className="min-h-dvh flex flex-col items-center gap-6 px-4 py-6 max-w-xl mx-auto">
      <div className="text-center">
        <h1 className="font-display text-3xl md:text-4xl font-extrabold text-knight-blue-dark">
          Tiny Knights
        </h1>
        <p className="font-display text-lg md:text-xl text-amber-500 font-bold">Times Table Quest</p>
      </div>

      <div className="flex flex-col items-center gap-2">
        <div className="rounded-full bg-white border-4 border-knight-blue/20 p-6 shadow-md">
          <KnightSprite state="idle" size="lg" />
        </div>
        <p className="font-display font-bold text-lg text-gray-700">Hi, {progress.childName}!</p>
      </div>

      <div className="w-full flex items-center justify-center gap-6">
        <div className="flex items-center gap-2 bg-orange-50 border-2 border-orange-200 rounded-full px-4 py-2">
          <span className="text-xl" aria-hidden="true">🔥</span>
          <span className="font-bold text-orange-700">{progress.dailyStreak} day streak</span>
        </div>
        <div className="flex items-center gap-2 bg-amber-50 border-2 border-amber-200 rounded-full px-4 py-2">
          <span className="text-xl" aria-hidden="true">🪙</span>
          <span className="font-bold text-amber-700">{progress.coins}</span>
        </div>
      </div>

      <div className="w-full max-w-sm">
        <div className="flex items-center justify-between mb-1">
          <span className="font-display font-bold text-gray-700">Level {level}</span>
          <span className="text-sm text-gray-500">{current}/{needed} XP</span>
        </div>
        <ProgressBar current={current} max={needed} label="" colorClass="bg-gold" />
      </div>

      <button
        onClick={onStartDailyQuest}
        className="w-full max-w-sm rounded-3xl bg-knight-blue text-white font-display text-2xl font-extrabold py-5 shadow-lg hover:bg-knight-blue-dark active:scale-95 transition-all animate-level-glow"
      >
        ⚔️ Start Daily Quest
      </button>

      <div className="w-full max-w-sm grid grid-cols-2 gap-3">
        <button
          onClick={() => onNavigate('modeSelect')}
          className="rounded-2xl bg-white border-2 border-knight-blue/20 font-display font-bold text-knight-blue-dark py-4 shadow-sm hover:bg-knight-blue/5 active:scale-95 transition-all"
        >
          🗺️ Quest Modes
        </button>
        <button
          onClick={() => onNavigate('settings')}
          className="rounded-2xl bg-white border-2 border-knight-blue/20 font-display font-bold text-knight-blue-dark py-4 shadow-sm hover:bg-knight-blue/5 active:scale-95 transition-all"
        >
          ⚙️ Settings
        </button>
      </div>

      <button
        onClick={() => onNavigate('parent')}
        className="text-sm text-gray-400 underline hover:text-gray-600"
      >
        Parent Dashboard
      </button>
    </div>
  );
}
