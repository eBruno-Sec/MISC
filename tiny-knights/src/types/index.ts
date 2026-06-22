export type FactKey = `${number}x${number}`;

export type MasteryLevel = 0 | 1 | 2 | 3 | 4 | 5;

export type Difficulty = 'easy' | 'normal' | 'challenge';

export type FactState = {
  key: FactKey;
  a: number;
  b: number;
  answer: number;
  attempts: number;
  correct: number;
  incorrect: number;
  currentStreak: number;
  bestStreak: number;
  responseMsTotal: number;
  averageResponseMs: number | null;
  lastResponseMs: number | null;
  masteryLevel: MasteryLevel;
  dueAt: string;
  lastSeenAt: string | null;
  lastIncorrectAt: string | null;
  correctSessionIds: string[];
  isMastered: boolean;
};

export type GameMode = 'dailyQuest' | 'tableTrainer' | 'speedRound' | 'bossBattle' | 'mistakeRescue';

export type SelectionBucket = 'coverage' | 'weak' | 'progression' | 'mixedUnmastered' | 'masteredReview';

export type QuestionType = 'standard' | 'missingFactor' | 'multipleChoice';

export type PlannedQuestion = {
  factKey: FactKey;
  bucket: SelectionBucket;
  questionType: QuestionType;
};

export type PracticeSession = {
  id: string;
  startedAt: string;
  endedAt: string | null;
  mode: GameMode;
  questionsAnswered: number;
  correct: number;
  incorrect: number;
  averageResponseMs: number | null;
  factsPracticed: FactKey[];
  factsMastered: FactKey[];
  missedFacts: FactKey[];
};

export type AppSettings = {
  sessionQuestionCount: number;
  maxFactor: 10 | 12;
  timedModeEnabled: boolean;
  soundEnabled: boolean;
  reducedMotion: boolean;
  darkMode: boolean;
  difficulty: Difficulty;
};

export type Badge = {
  id: string;
  name: string;
  description: string;
  icon: string;
  earnedAt: string | null;
};

export type CosmeticUnlock = {
  id: string;
  name: string;
  type: 'sword' | 'shield' | 'helmet';
  icon: string;
  unlockedAt: string | null;
};

export type MonsterBookEntry = {
  monsterId: string;
  defeats: number;
  firstSeenAt: string | null;
};

export type QuestCompletion = {
  questId: string;
  mode: GameMode;
  table?: number;
  bossId?: string;
  timesCompleted: number;
  bestAccuracy: number;
  bestStreak: number;
  lastCompletedAt: string;
  starsEarned: number;
};

export type UserProgress = {
  childName: string;
  avatarId: string;
  maxFactor: 10 | 12;
  xp: number;
  coins: number;
  dailyStreak: number;
  lastPlayedDate: string | null;
  coverageCursor: number;
  facts: Record<FactKey, FactState>;
  sessions: PracticeSession[];
  badges: Badge[];
  cosmetics: CosmeticUnlock[];
  monsterBook: MonsterBookEntry[];
  settings: AppSettings;
  questCompletions: Record<string, QuestCompletion>;
};

export type Monster = {
  id: string;
  name: string;
  emoji: string;
  table: number;
  hpMultiplier: number;
  difficultyLabel?: string;
  unlockTable?: number;
};

export type World = {
  id: number | 'mixed';
  name: string;
  emoji: string;
  table: number | null;
};

export type AnswerResult = {
  isCorrect: boolean;
  responseMs: number;
  userAnswer: number;
};

export type FeedbackKind = 'correct' | 'incorrect' | 'slow' | 'hint';
