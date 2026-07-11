import { useEffect, useRef, useState } from 'react';
import type { GameMode, UserProgress, Badge, CosmeticUnlock } from './types';
import { loadProgress, saveProgress, resetProgress } from './lib/storage';
import { checkAndAwardBadges, checkCosmeticUnlocks, getLevelFromXp, recordQuestCompletion } from './lib/rewards';
import { advanceDailyStreak } from './lib/dates';
import { setSoundEnabled } from './lib/sound';
import { initAnalytics, trackScreen } from './lib/analytics';
import HomeScreen from './screens/HomeScreen';
import ModeSelectScreen from './screens/ModeSelectScreen';
import BossSelectScreen from './screens/BossSelectScreen';
import PracticeScreen, { type SessionResult } from './screens/PracticeScreen';
import VictoryScreen from './screens/VictoryScreen';
import ParentScreen from './screens/ParentScreen';
import SettingsScreen from './screens/SettingsScreen';

type Screen = 'home' | 'modeSelect' | 'bossSelect' | 'practice' | 'victory' | 'parent' | 'settings';

type VictoryData = {
  result: SessionResult;
  newlyEarnedBadges: Badge[];
  newlyUnlockedCosmetics: CosmeticUnlock[];
};

export default function App() {
  const [progress, setProgress] = useState<UserProgress>(() => loadProgress());
  const [screen, setScreen] = useState<Screen>('home');
  const [activeMode, setActiveMode] = useState<GameMode>('dailyQuest');
  const [activeTable, setActiveTable] = useState<number | undefined>(undefined);
  const [activeBossId, setActiveBossId] = useState<string | undefined>(undefined);
  const [sessionKey, setSessionKey] = useState(0);
  const [victoryData, setVictoryData] = useState<VictoryData | null>(null);

  // Debounce saves to ~1.5 s to avoid serialising the full progress object on
  // every individual React state update (answers, animations, coin ticks, etc.).
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current = setTimeout(() => saveProgress(progress), 1500);
    return () => { if (saveTimer.current) clearTimeout(saveTimer.current); };
  }, [progress]);

  useEffect(() => {
    const root = document.documentElement;
    if (progress.settings.reducedMotion) {
      root.classList.add('reduced-motion');
    } else {
      root.classList.remove('reduced-motion');
    }
  }, [progress.settings.reducedMotion]);

  useEffect(() => {
    const root = document.documentElement;
    if (progress.settings.darkMode) {
      root.classList.add('dark');
    } else {
      root.classList.remove('dark');
    }
  }, [progress.settings.darkMode]);

  useEffect(() => {
    setSoundEnabled(progress.settings.soundEnabled);
  }, [progress.settings.soundEnabled]);

  useEffect(() => {
    initAnalytics();
  }, []);

  useEffect(() => {
    trackScreen(screen);
  }, [screen]);

  function startQuest(mode: GameMode, table?: number, bossId?: string) {
    setActiveMode(mode);
    setActiveTable(table);
    setActiveBossId(bossId);
    setSessionKey((k) => k + 1);
    setScreen('practice');
  }

  function handleFinishSession(result: SessionResult) {
    const { updatedProgress, session, bossWon, completed } = result;

    const practicedTables = new Set<number>();
    session.factsPracticed.forEach((key) => {
      const [a] = key.split('x').map(Number);
      practicedTables.add(a);
    });

    const afterLevel = getLevelFromXp(updatedProgress.xp);

    const { badges, newlyEarned } = checkAndAwardBadges(
      updatedProgress,
      session.mode,
      session.missedFacts.length,
      session.factsMastered,
      bossWon,
      practicedTables,
      completed
    );

    const { cosmetics, newlyUnlocked } = checkCosmeticUnlocks(updatedProgress, afterLevel);

    const { dailyStreak, lastPlayedDate } = advanceDailyStreak(
      updatedProgress.lastPlayedDate,
      updatedProgress.dailyStreak
    );

    const accuracy =
      session.questionsAnswered > 0 ? Math.round((session.correct / session.questionsAnswered) * 100) : 0;
    const stars = accuracy >= 90 ? 3 : accuracy >= 70 ? 2 : accuracy >= 40 ? 1 : 0;
    // Only fully played sessions count as quest completions
    const questCompletions = completed
      ? recordQuestCompletion(
          updatedProgress,
          session.mode,
          activeTable,
          accuracy,
          session.correct,
          stars,
          activeBossId
        )
      : updatedProgress.questCompletions;

    const finalProgress: UserProgress = {
      ...updatedProgress,
      badges,
      cosmetics,
      dailyStreak,
      lastPlayedDate,
      questCompletions,
    };

    setProgress(finalProgress);

    // Defeats and early exits save progress silently; PracticeScreen stays in
    // control of what the player sees (defeat screen, or the exit navigation).
    if (!completed) return;

    setVictoryData({
      result: { ...result, updatedProgress: finalProgress },
      newlyEarnedBadges: newlyEarned,
      newlyUnlockedCosmetics: newlyUnlocked,
    });
    setScreen('victory');
  }

  function handleUpdateProgress(updated: UserProgress) {
    setProgress(updated);
  }

  function handleReset() {
    const fresh = resetProgress();
    setProgress(fresh);
    setScreen('home');
  }

  function renderScreen() {
    if (screen === 'modeSelect') {
      return (
        <ModeSelectScreen
          progress={progress}
          onSelectTableTrainer={(table) => startQuest('tableTrainer', table)}
          onSelectBossBattle={() => setScreen('bossSelect')}
          onSelectMistakeRescue={() => startQuest('mistakeRescue')}
          onSelectSpeedRound={() => startQuest('speedRound')}
          onBack={() => setScreen('home')}
        />
      );
    }

    if (screen === 'bossSelect') {
      return (
        <BossSelectScreen
          progress={progress}
          onSelectBoss={(bossId) => startQuest('bossBattle', undefined, bossId)}
          onBack={() => setScreen('modeSelect')}
        />
      );
    }

    if (screen === 'practice') {
      return (
        <PracticeScreen
          key={sessionKey}
          progress={progress}
          mode={activeMode}
          table={activeTable}
          bossId={activeBossId}
          onFinish={handleFinishSession}
          onExit={() => setScreen('home')}
          onRetry={() => startQuest(activeMode, activeTable, activeBossId)}
          onPracticeWeakFacts={() => startQuest('mistakeRescue')}
        />
      );
    }

    if (screen === 'victory' && victoryData) {
      return (
        <VictoryScreen
          session={victoryData.result.session}
          xpEarned={victoryData.result.xpEarned}
          coinsEarned={victoryData.result.coinsEarned}
          newlyEarnedBadges={victoryData.newlyEarnedBadges.map((b) => ({ id: b.id, name: b.name, icon: b.icon }))}
          newlyUnlockedCosmetics={victoryData.newlyUnlockedCosmetics.map((c) => ({ id: c.id, name: c.name, icon: c.icon }))}
          bossWon={victoryData.result.bossWon}
          progress={progress}
          onContinue={() => startQuest('dailyQuest')}
          onHome={() => setScreen('home')}
        />
      );
    }

    if (screen === 'parent') {
      return (
        <ParentScreen
          progress={progress}
          onUpdateProgress={handleUpdateProgress}
          onReset={handleReset}
          onBack={() => setScreen('home')}
        />
      );
    }

    if (screen === 'settings') {
      return (
        <SettingsScreen
          progress={progress}
          onUpdateProgress={handleUpdateProgress}
          onBack={() => setScreen('home')}
        />
      );
    }

    return (
      <HomeScreen
        progress={progress}
        onStartDailyQuest={() => startQuest('dailyQuest')}
        onNavigate={(target) => setScreen(target)}
      />
    );
  }

  // Keying on the screen name re-runs the entry animation on every navigation.
  return (
    <div key={screen} className="screen-in">
      {renderScreen()}
    </div>
  );
}
