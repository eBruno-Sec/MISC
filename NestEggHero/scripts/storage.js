export const LEARNING_SCHEMA_VERSION = "1.0.0";
const DB_NAME = "nestegghero";
const DB_VERSION = 1;
const STORE_NAME = "records";
const LEARNING_KEY = "learning";
const PREFS_KEY = "nestegghero.preferences";

export function defaultPreferences() {
  return { theme: "light", kidSpeak: false, textSize: "normal" };
}

export function defaultLearning() {
  const now = new Date().toISOString();
  return {
    schemaVersion: LEARNING_SCHEMA_VERSION,
    createdAt: now,
    updatedAt: now,
    readLessons: {},
    bookmarks: [],
    highlights: [],
    quizScores: {},
    badges: [],
    streak: { count: 0, lastActiveDay: "", graceUsedOn: "" },
    calculatorRuns: {},
    events: {}
  };
}

export function loadPreferences() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return defaultPreferences();
    const parsed = JSON.parse(raw);
    return {
      theme: parsed.theme === "dark" ? "dark" : parsed.theme === "light" ? "light" : defaultPreferences().theme,
      kidSpeak: parsed.kidSpeak === true,
      textSize: parsed.textSize === "large" ? "large" : "normal"
    };
  } catch {
    return defaultPreferences();
  }
}

export function savePreferences(preferences) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(preferences));
    return true;
  } catch {
    return false;
  }
}

let dbPromise = null;

function openDatabase() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is unavailable."));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open local storage."));
    request.onblocked = () => reject(new Error("Local storage is blocked by another tab."));
  });
  dbPromise.catch(() => { dbPromise = null; });
  return dbPromise;
}

function migrateLearning(stored) {
  if (!stored || stored.schemaVersion !== LEARNING_SCHEMA_VERSION) return defaultLearning();
  const base = defaultLearning();
  return { ...base, ...stored, streak: { ...base.streak, ...(stored.streak || {}) } };
}

export async function loadLearning() {
  try {
    const db = await openDatabase();
    const stored = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(LEARNING_KEY);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return { learning: migrateLearning(stored), persisted: true };
  } catch {
    return { learning: defaultLearning(), persisted: false };
  }
}

export async function persistLearning(learning) {
  const record = { ...learning, updatedAt: new Date().toISOString() };
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(record, LEARNING_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("Save failed."));
    tx.onabort = () => reject(tx.error || new Error("Save was interrupted."));
  });
  return record;
}

export function createAutosaver(onError) {
  let timer = null;
  let pending = null;
  const flush = async () => {
    const snapshot = pending;
    pending = null;
    if (!snapshot) return;
    try {
      await persistLearning(snapshot);
    } catch (error) {
      if (typeof onError === "function") onError(error);
    }
  };
  return {
    queue(learning) {
      pending = learning;
      if (timer) clearTimeout(timer);
      timer = setTimeout(flush, 600);
    },
    async flushNow() {
      if (timer) clearTimeout(timer);
      timer = null;
      await flush();
    }
  };
}
