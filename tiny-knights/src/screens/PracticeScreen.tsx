import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  FactKey,
  FeedbackKind,
  GameMode,
  Monster,
  PlannedQuestion,
  PracticeSession,
  UserProgress,
} from '../types';
import {
  buildBossBattlePlan,
  buildDailyQuestPlan,
  buildMistakeRescuePlan,
  buildTableTrainerPlan,
  insertCommutativePair,
  rescheduleMissedFact,
} from '../lib/questionPlanner';
import { getFeedbackTier, getRandomFeedback, updateFactAfterAnswer } from '../lib/answerChecking';
import {
  generateMultipleChoiceOptions,
  getCommutativeHint,
  getHintForFact,
} from '../lib/hints';
import {
  KNIGHT_BASE_ENERGY,
  clampHp,
  getAttackDamage,
  getBlockEnergyLoss,
  getMonsterMaxHp,
  spawnMonster,
} from '../lib/battleEngine';
import { calculateCoinsForAnswer, calculateXpForAnswer } from '../lib/rewards';
import { playSfx } from '../lib/sound';
import { getWorldForTable } from '../data/worlds';
import BattleArena from '../components/BattleArena';
import QuestionCard from '../components/QuestionCard';
import NumberPad from '../components/NumberPad';
import FeedbackToast from '../components/FeedbackToast';
import type { KnightState } from '../components/KnightSprite';
import type { MonsterAnimState } from '../components/MonsterSprite';

type PracticeScreenProps = {
  progress: UserProgress;
  mode: GameMode;
  table?: number;
  bossId?: string;
  onFinish: (result: SessionResult) => void;
  onExit: () => void;
  onRetry: () => void;
  onPracticeWeakFacts: () => void;
};

export type SessionResult = {
  session: PracticeSession;
  updatedProgress: UserProgress;
  xpEarned: number;
  coinsEarned: number;
  bossWon: boolean;
  /** False when the knight was defeated or the player left early — progress
      still saves, but no victory screen or quest completion is recorded. */
  completed: boolean;
};

/**
 * Fresh values for the answer being processed. finishSession runs inside
 * setTimeout callbacks whose closures predate the last setState, so the final
 * answer of a session would otherwise be dropped from the results.
 */
type SessionOverrides = {
  bossWon?: boolean;
  facts?: UserProgress['facts'];
  correctCount?: number;
  incorrectCount?: number;
  questionsAnswered?: number;
  responseTimesMs?: number[];
  factsPracticed?: Set<FactKey>;
  factsMastered?: Set<FactKey>;
  missedFacts?: Set<FactKey>;
  monsterDefeats?: Record<string, number>;
  xpEarned?: number;
  coinsEarned?: number;
};

const SPEED_ROUND_SECONDS = 60;

function getFastThreshold(difficulty: UserProgress['settings']['difficulty']) {
  if (difficulty === 'easy') return 6000;
  if (difficulty === 'challenge') return 3000;
  return 4000;
}

function buildInitialPlan(params: {
  progress: UserProgress;
  mode: GameMode;
  table?: number;
  monster: Monster;
}): { plan: PlannedQuestion[]; nextCursor: number } {
  const { progress, mode, table, monster } = params;
  const now = new Date();

  if (mode === 'dailyQuest') {
    const result = buildDailyQuestPlan({
      facts: progress.facts,
      maxFactor: progress.maxFactor,
      sessionQuestionCount: progress.settings.sessionQuestionCount,
      coverageCursor: progress.coverageCursor,
      now,
    });
    return { plan: result.plan, nextCursor: result.nextCoverageCursor };
  }

  if (mode === 'tableTrainer' && table) {
    return {
      plan: buildTableTrainerPlan({
        facts: progress.facts,
        table,
        maxFactor: progress.maxFactor,
        sessionQuestionCount: Math.min(progress.settings.sessionQuestionCount, 15),
        now,
      }),
      nextCursor: progress.coverageCursor,
    };
  }

  if (mode === 'bossBattle') {
    const bossMaxFactor =
      monster.unlockTable && monster.unlockTable > 0
        ? Math.min(progress.maxFactor, monster.unlockTable)
        : progress.maxFactor;
    const priority = Object.values(progress.facts)
      .filter((f) => f.a <= bossMaxFactor && f.b <= bossMaxFactor && f.lastIncorrectAt && !f.isMastered)
      .sort((a, b) => new Date(b.lastIncorrectAt!).getTime() - new Date(a.lastIncorrectAt!).getTime())
      .slice(0, 5)
      .map((f) => f.key);
    return {
      plan: buildBossBattlePlan({
        facts: progress.facts,
        maxFactor: bossMaxFactor,
        sessionQuestionCount: getMonsterMaxHp(monster, 'bossBattle'),
        priorityFacts: priority,
        now,
      }),
      nextCursor: progress.coverageCursor,
    };
  }

  if (mode === 'mistakeRescue') {
    return {
      plan: buildMistakeRescuePlan({
        facts: progress.facts,
        maxFactor: progress.maxFactor,
        sessionQuestionCount: Math.min(progress.settings.sessionQuestionCount, 15),
      }),
      nextCursor: progress.coverageCursor,
    };
  }

  // speedRound: oversized pool, the 60-second timer decides how far we get
  return {
    plan: buildMistakeRescuePlan({
      facts: progress.facts,
      maxFactor: progress.maxFactor,
      sessionQuestionCount: 60,
    }),
    nextCursor: progress.coverageCursor,
  };
}

export default function PracticeScreen({ progress, mode, table, bossId, onFinish, onExit, onRetry, onPracticeWeakFacts }: PracticeScreenProps) {
  const sessionId = useRef(`session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`).current;
  const startedAt = useRef(new Date().toISOString()).current;

  const [facts, setFacts] = useState(progress.facts);

  const [monster, setMonster] = useState(() =>
    spawnMonster(table ?? Math.floor(Math.random() * progress.maxFactor) + 1, mode, bossId)
  );
  const [monsterHp, setMonsterHp] = useState(() => getMonsterMaxHp(monster, mode));
  const [knightEnergy, setKnightEnergy] = useState(KNIGHT_BASE_ENERGY);

  // The session plan is computed once, synchronously, on first render.
  const [initialPlanState] = useState(() => buildInitialPlan({ progress, mode, table, monster }));
  const [plan, setPlan] = useState<PlannedQuestion[]>(initialPlanState.plan);
  const coverageCursor = initialPlanState.nextCursor;
  const [planIndex, setPlanIndex] = useState(0);

  const [wrongAttempts, setWrongAttempts] = useState(0);
  const [answerValue, setAnswerValue] = useState('');
  const [feedback, setFeedback] = useState<{ message: string; kind: FeedbackKind } | null>(null);
  const [showMultipleChoice, setShowMultipleChoice] = useState(false);
  const [mcOptions, setMcOptions] = useState<number[]>([]);

  const [knightState, setKnightState] = useState<KnightState>('idle');
  const [monsterState, setMonsterState] = useState<MonsterAnimState>('idle');
  const [attackTrigger, setAttackTrigger] = useState(0);
  const [blockTrigger, setBlockTrigger] = useState(0);

  const [questionStart, setQuestionStart] = useState<number>(Date.now());
  const [questionsAnswered, setQuestionsAnswered] = useState(0);
  const [correctCount, setCorrectCount] = useState(0);
  const [incorrectCount, setIncorrectCount] = useState(0);
  const [responseTimesMs, setResponseTimesMs] = useState<number[]>([]);
  const [factsPracticed, setFactsPracticed] = useState<Set<FactKey>>(new Set());
  const [factsMastered, setFactsMastered] = useState<Set<FactKey>>(new Set());
  const [missedFacts, setMissedFacts] = useState<Set<FactKey>>(new Set());
  const [monsterDefeats, setMonsterDefeats] = useState<Record<string, number>>({});
  const [xpEarned, setXpEarned] = useState(0);
  const [coinsEarned, setCoinsEarned] = useState(0);
  const [bossWon, setBossWon] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [battleStatus, setBattleStatus] = useState<'active' | 'victory' | 'defeat'>('active');

  const [timeLeft, setTimeLeft] = useState(SPEED_ROUND_SECONDS);

  const reducedMotion = progress.settings.reducedMotion;

  // Speed round timer; finishSession is guarded by isComplete so it runs once
  useEffect(() => {
    if (mode !== 'speedRound' || battleStatus !== 'active') return;
    if (timeLeft <= 0) {
      finishSession();
      return;
    }
    const timer = setTimeout(() => setTimeLeft((t) => t - 1), 1000);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeLeft, mode, battleStatus]);

  const currentQuestion = plan[planIndex];
  const currentFact = currentQuestion ? facts[currentQuestion.factKey] : undefined;

  const hiddenSlot: 'a' | 'b' | 'product' = useMemo(() => {
    if (!currentQuestion || currentQuestion.questionType !== 'missingFactor') return 'product';
    return Math.random() < 0.5 ? 'a' : 'b';
  }, [currentQuestion]);

  const expectedAnswer = useMemo(() => {
    if (!currentFact) return 0;
    if (currentQuestion?.questionType === 'missingFactor') {
      return hiddenSlot === 'a' ? currentFact.a : currentFact.b;
    }
    return currentFact.answer;
  }, [currentFact, currentQuestion, hiddenSlot]);

  const monsterMaxHp = getMonsterMaxHp(monster, mode);

  function handleDigit(d: string) {
    if (battleStatus !== 'active') return;
    if (answerValue.length >= 3) return;
    playSfx('tap');
    setAnswerValue((v) => v + d);
  }

  function handleBackspace() {
    if (battleStatus !== 'active') return;
    setAnswerValue((v) => v.slice(0, -1));
  }

  function finishSession(overrides?: SessionOverrides, completed = true) {
    if (isComplete) return;
    setIsComplete(true);

    const finalFacts = overrides?.facts ?? facts;
    const finalCorrectCount = overrides?.correctCount ?? correctCount;
    const finalIncorrectCount = overrides?.incorrectCount ?? incorrectCount;
    const finalQuestionsAnswered = overrides?.questionsAnswered ?? questionsAnswered;
    const finalResponseTimesMs = overrides?.responseTimesMs ?? responseTimesMs;
    const finalFactsPracticed = overrides?.factsPracticed ?? factsPracticed;
    const finalFactsMastered = overrides?.factsMastered ?? factsMastered;
    const finalMissedFacts = overrides?.missedFacts ?? missedFacts;
    const finalMonsterDefeats = overrides?.monsterDefeats ?? monsterDefeats;
    const finalXpEarned = overrides?.xpEarned ?? xpEarned;
    const finalCoinsEarned = overrides?.coinsEarned ?? coinsEarned;
    const finalBossWon = overrides?.bossWon ?? bossWon;

    const avgResponse =
      finalResponseTimesMs.length > 0
        ? finalResponseTimesMs.reduce((a, b) => a + b, 0) / finalResponseTimesMs.length
        : null;

    const session: PracticeSession = {
      id: sessionId,
      startedAt,
      endedAt: new Date().toISOString(),
      mode,
      questionsAnswered: finalQuestionsAnswered,
      correct: finalCorrectCount,
      incorrect: finalIncorrectCount,
      averageResponseMs: avgResponse,
      factsPracticed: Array.from(finalFactsPracticed),
      factsMastered: Array.from(finalFactsMastered),
      missedFacts: Array.from(finalMissedFacts),
    };

    const updatedMonsterBook = [...progress.monsterBook];
    for (const [monsterId, count] of Object.entries(finalMonsterDefeats)) {
      const existing = updatedMonsterBook.find((m) => m.monsterId === monsterId);
      if (existing) {
        existing.defeats += count;
      } else {
        updatedMonsterBook.push({ monsterId, defeats: count, firstSeenAt: new Date().toISOString() });
      }
    }

    // Daily streak and lastPlayedDate are advanced in one place: App.handleFinishSession.
    const updatedProgress: UserProgress = {
      ...progress,
      facts: finalFacts,
      coverageCursor,
      xp: progress.xp + finalXpEarned,
      coins: progress.coins + finalCoinsEarned,
      // keep only the most recent sessions so localStorage doesn't grow forever
      sessions: [...progress.sessions, session].slice(-50),
      monsterBook: updatedMonsterBook,
    };

    onFinish({
      session,
      updatedProgress,
      xpEarned: finalXpEarned,
      coinsEarned: finalCoinsEarned,
      bossWon: finalBossWon,
      completed,
    });
  }

  /** Save partial progress when leaving mid-session, then hand control back. */
  function handleExit() {
    if (!isComplete && questionsAnswered > 0) {
      finishSession(undefined, false);
    }
    onExit();
  }

  function advanceToNext(newPlan?: PlannedQuestion[], overrides?: SessionOverrides) {
    const activePlan = newPlan ?? plan;
    const nextIndex = planIndex + 1;

    if (nextIndex >= activePlan.length) {
      finishSession(overrides);
      return;
    }

    setPlanIndex(nextIndex);
    setAnswerValue('');
    setWrongAttempts(0);
    setShowMultipleChoice(false);
    setFeedback(null);
    setQuestionStart(Date.now());
  }

  function spawnNewMonster(forTable?: number) {
    const nextTable = forTable ?? table ?? Math.floor(Math.random() * progress.maxFactor) + 1;
    const nextMonster = mode === 'bossBattle' ? monster : spawnMonster(nextTable, mode);
    setMonster(nextMonster);
    setMonsterHp(getMonsterMaxHp(nextMonster, mode));
    setMonsterState('idle');
  }

  function handleSubmit(submitted?: string) {
    // `submitted` lets multiple-choice pass its value directly instead of
    // waiting for the answerValue state update (which this closure can't see).
    const rawAnswer = submitted ?? answerValue;
    if (battleStatus !== 'active') return;
    if (!currentFact || !currentQuestion || rawAnswer === '') return;

    const userAnswer = Number(rawAnswer);
    const responseMs = Date.now() - questionStart;
    const isCorrect = userAnswer === expectedAnswer;
    const difficulty = progress.settings.difficulty;
    const fastThreshold = getFastThreshold(difficulty);
    const wasFast = responseMs <= fastThreshold;

    const now = new Date();
    const wasAlreadyMastered = currentFact.isMastered;
    const updatedFact = updateFactAfterAnswer({
      fact: currentFact,
      isCorrect,
      responseMs,
      sessionId,
      difficulty,
      now,
    });

    const newFacts = { ...facts, [currentFact.key]: updatedFact };
    setFacts(newFacts);

    setFactsPracticed((prev) => new Set(prev).add(currentFact.key));
    setResponseTimesMs((prev) => [...prev, responseMs]);
    setQuestionsAnswered((q) => q + 1);

    if (isCorrect) {
      setCorrectCount((c) => c + 1);
      if (!wasAlreadyMastered && updatedFact.isMastered) {
        setFactsMastered((prev) => new Set(prev).add(currentFact.key));
      }

      const tier = getFeedbackTier(true, responseMs, difficulty);
      setFeedback({ message: getRandomFeedback(tier), kind: tier === 'correct-fast' ? 'correct' : 'slow' });

      const earnedXp = calculateXpForAnswer(true, wasFast, currentQuestion.bucket);
      const earnedCoins = calculateCoinsForAnswer(true, wasFast);
      setXpEarned((x) => x + earnedXp);
      setCoinsEarned((c) => c + earnedCoins);

      setKnightState('attack');
      setAttackTrigger((t) => t + 1);

      const damage = getAttackDamage(wasFast, mode);
      const newHp = clampHp(monsterHp - damage, monsterMaxHp);
      setMonsterHp(newHp);
      playSfx(newHp <= 0 ? 'monsterDown' : 'correct');

      const overrides: SessionOverrides = {
        facts: newFacts,
        correctCount: correctCount + 1,
        questionsAnswered: questionsAnswered + 1,
        responseTimesMs: [...responseTimesMs, responseMs],
        factsPracticed: new Set(factsPracticed).add(currentFact.key),
        factsMastered:
          !wasAlreadyMastered && updatedFact.isMastered
            ? new Set(factsMastered).add(currentFact.key)
            : factsMastered,
        xpEarned: xpEarned + earnedXp,
        coinsEarned: coinsEarned + earnedCoins,
      };

      if (newHp <= 0) {
        setMonsterState('defeated');
        const updatedMonsterDefeats = { ...monsterDefeats, [monster.id]: (monsterDefeats[monster.id] ?? 0) + 1 };
        setMonsterDefeats(updatedMonsterDefeats);
        overrides.monsterDefeats = updatedMonsterDefeats;

        if (mode === 'bossBattle') {
          setBossWon(true);
          setTimeout(() => finishSession({ ...overrides, bossWon: true }), reducedMotion ? 100 : 700);
        } else {
          const monsterTable = currentFact.b <= progress.maxFactor ? currentFact.b : currentFact.a;
          setTimeout(() => spawnNewMonster(monsterTable), reducedMotion ? 0 : 500);
          setTimeout(() => advanceToNext(plan, overrides), reducedMotion ? 100 : 700);
        }
      } else {
        setMonsterState('hurt');
        setTimeout(() => setMonsterState('idle'), reducedMotion ? 0 : 400);
        setTimeout(() => advanceToNext(undefined, overrides), reducedMotion ? 100 : 600);
      }
    } else {
      playSfx('incorrect');
      setIncorrectCount((c) => c + 1);
      setMissedFacts((prev) => new Set(prev).add(currentFact.key));

      const newWrongAttempts = wrongAttempts + 1;
      setWrongAttempts(newWrongAttempts);

      setKnightState('block');
      setBlockTrigger((t) => t + 1);
      const energyLoss = getBlockEnergyLoss();
      const newEnergy = clampHp(knightEnergy - energyLoss, KNIGHT_BASE_ENERGY);
      setKnightEnergy(newEnergy);

      if (newEnergy <= 0) {
        setFeedback({
          message: `${getRandomFeedback('incorrect')} The answer is ${currentFact.answer}.`,
          kind: 'incorrect',
        });
        setAnswerValue('');
        setShowMultipleChoice(false);
        // Defeat still saves the session: the correct answers a kid earned
        // before going down should never vanish.
        const defeatOverrides: SessionOverrides = {
          facts: newFacts,
          incorrectCount: incorrectCount + 1,
          questionsAnswered: questionsAnswered + 1,
          responseTimesMs: [...responseTimesMs, responseMs],
          factsPracticed: new Set(factsPracticed).add(currentFact.key),
          missedFacts: new Set(missedFacts).add(currentFact.key),
        };
        setTimeout(() => {
          setBattleStatus('defeat');
          finishSession(defeatOverrides, false);
        }, reducedMotion ? 0 : 500);
        return;
      }

      if (newWrongAttempts === 1) {
        setFeedback({ message: getHintForFact(currentFact), kind: 'incorrect' });
      } else if (newWrongAttempts === 2) {
        const options = generateMultipleChoiceOptions(currentFact.answer, currentFact.a, currentFact.b);
        setMcOptions(options);
        setShowMultipleChoice(true);
        setFeedback({
          message: `Hint: ${getCommutativeHint(currentFact.a, currentFact.b)} Pick the answer below.`,
          kind: 'hint',
        });
      } else {
        setFeedback({
          message: `${getRandomFeedback('incorrect')} The answer is ${currentFact.answer}.`,
          kind: 'incorrect',
        });
      }

      setAnswerValue('');

      // Reschedule missed fact and commutative pair (not in mistake rescue)
      if (newWrongAttempts >= 3) {
        let updatedPlan = rescheduleMissedFact(plan, planIndex, currentFact.key, mode);
        updatedPlan = insertCommutativePair(updatedPlan, planIndex, currentFact.key, currentQuestion.bucket);
        setPlan(updatedPlan);

        const overrides: SessionOverrides = {
          facts: newFacts,
          incorrectCount: incorrectCount + 1,
          questionsAnswered: questionsAnswered + 1,
          responseTimesMs: [...responseTimesMs, responseMs],
          factsPracticed: new Set(factsPracticed).add(currentFact.key),
          missedFacts: new Set(missedFacts).add(currentFact.key),
        };
        setTimeout(() => advanceToNext(updatedPlan, overrides), reducedMotion ? 100 : 1400);
      }
    }
  }

  function handleMultipleChoiceSelect(value: number) {
    setAnswerValue(String(value));
    handleSubmit(String(value));
  }

  // Keyboard support
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (isComplete || battleStatus !== 'active') return;
      if (e.key >= '0' && e.key <= '9') {
        handleDigit(e.key);
      } else if (e.key === 'Backspace') {
        handleBackspace();
      } else if (e.key === 'Enter') {
        handleSubmit();
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [answerValue, planIndex, isComplete, battleStatus]);

  if (plan.length === 0) {
    // e.g. Mistake Rescue with nothing missed and everything mastered
    return (
      <div className="flex flex-col items-center justify-center min-h-[80vh] gap-6 px-4 py-6 text-center max-w-md mx-auto">
        <div className="text-6xl" aria-hidden="true">🏰✨</div>
        <h1 className="font-display text-3xl font-extrabold text-knight-blue-dark">All Clear, Brave Knight!</h1>
        <p className="text-gray-600 font-bold">
          There's nothing to practice here right now. Pick another quest from the map!
        </p>
        <button
          onClick={onExit}
          className="w-full rounded-2xl bg-knight-blue text-white font-display font-extrabold text-lg py-3 shadow-md hover:bg-knight-blue-dark transition-colors"
        >
          Return to Map
        </button>
      </div>
    );
  }

  if (!currentQuestion || !currentFact) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-4">
        <p className="font-display text-xl text-gray-600">Preparing your quest...</p>
      </div>
    );
  }

  if (battleStatus === 'defeat') {
    return (
      <div className="flex flex-col items-center justify-center min-h-[80vh] gap-6 px-4 py-6 text-center max-w-md mx-auto">
        <div className="text-6xl" aria-hidden="true">🛡️💥</div>
        <h1 className="font-display text-3xl font-extrabold text-knight-blue-dark">Knocked Down!</h1>
        <p className="text-gray-600 font-bold">
          {monster.name} got the upper hand this time. Every great knight loses a battle before winning the war.
        </p>
        <div className="flex flex-col gap-3 w-full">
          <button
            onClick={onRetry}
            className="rounded-2xl bg-knight-blue text-white font-display font-extrabold text-lg py-3 shadow-md hover:bg-knight-blue-dark transition-colors"
          >
            Try Again
          </button>
          <button
            onClick={onPracticeWeakFacts}
            className="rounded-2xl bg-gold text-knight-blue-dark font-display font-extrabold text-lg py-3 shadow-md hover:brightness-105 transition-all"
          >
            Practice Weak Facts
          </button>
          <button
            onClick={onExit}
            className="rounded-2xl bg-white border-2 border-gray-200 text-gray-600 font-display font-extrabold text-lg py-3 shadow-sm hover:bg-gray-50 transition-colors"
          >
            Return to Map
          </button>
        </div>
      </div>
    );
  }

  const world = table ? getWorldForTable(table) : getWorldForTable(currentFact.b <= 12 ? currentFact.b : currentFact.a);

  return (
    <div className="min-h-dvh px-4 py-4 max-w-5xl mx-auto flex flex-col gap-3">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <button
          onClick={handleExit}
          className="rounded-full bg-white border-2 border-gray-200 w-10 h-10 flex items-center justify-center text-xl text-gray-700 shadow-sm hover:bg-gray-50"
          aria-label="Exit to home"
        >
          ←
        </button>
        <div className="font-display font-bold text-gray-600 text-sm">
          {mode === 'speedRound' ? (
            <span>⏱️ {timeLeft}s</span>
          ) : (
            <span>
              Question {Math.min(planIndex + 1, plan.length)}/{plan.length}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 text-sm font-bold text-amber-600">
          <span aria-hidden="true">🪙</span> {progress.coins + coinsEarned}
        </div>
      </div>

      {/* Body: portrait = column, landscape = row */}
      <div className="flex flex-col landscape:flex-row gap-3 flex-1">

        {/* Arena — takes more space in landscape */}
        <div className="landscape:w-1/2 landscape:flex landscape:items-center">
          <div className="w-full">
            <BattleArena
              monster={monster}
              monsterHp={monsterHp}
              monsterMaxHp={monsterMaxHp}
              knightEnergy={knightEnergy}
              knightMaxEnergy={KNIGHT_BASE_ENERGY}
              knightState={knightState}
              monsterState={monsterState}
              attackTrigger={attackTrigger}
              blockTrigger={blockTrigger}
              worldName={world.name}
              worldEmoji={world.emoji}
            />
          </div>
        </div>

        {/* Question + Pad */}
        <div className="landscape:w-1/2 landscape:flex landscape:flex-col landscape:justify-center">
          <div className="rounded-3xl bg-white border-2 border-gray-100 shadow-sm p-4 flex flex-col gap-3">
            <QuestionCard
              a={currentFact.a}
              b={currentFact.b}
              questionType={showMultipleChoice ? 'multipleChoice' : currentQuestion.questionType}
              hiddenSlot={hiddenSlot}
              multipleChoiceOptions={mcOptions}
              onChoiceSelect={handleMultipleChoiceSelect}
            />

            {!showMultipleChoice && (
              <NumberPad
                value={answerValue}
                onDigit={handleDigit}
                onBackspace={handleBackspace}
                onSubmit={handleSubmit}
                disabled={battleStatus !== 'active'}
              />
            )}

            <FeedbackToast
              message={feedback?.message ?? ''}
              kind={feedback?.kind ?? 'hint'}
              visible={!!feedback}
            />
          </div>
        </div>

      </div>
    </div>
  );
}
