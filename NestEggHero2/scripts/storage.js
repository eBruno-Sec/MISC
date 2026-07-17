// Persistence. Learning state lives in IndexedDB; only low-risk display
// preferences live in localStorage. Nothing sensitive is ever persisted:
// no credentials, identifiers, account numbers, or financial records.
// Every persisted object carries schemaVersion, createdAt, and updatedAt,
// and a failed load or save must leave current in-memory state unchanged.

export const LEARNING_SCHEMA_VERSION = "1.0.0";

const DB_NAME = "nestegghero2";
const DB_VERSION = 1;
const STORE_NAME = "records";
const LEARNING_KEY = "learning";
const PREFS_KEY = "nestegghero2.preferences";

export function defaultPreferences() {
  // First visit resolves the OS preference once into a concrete theme;
  // after that the toggle is a plain two-state light/dark switch.
  const prefersDark = typeof matchMedia === "function" && matchMedia("(prefers-color-scheme: dark)").matches;
  return { theme: prefersDark ? "dark" : "light", kidSpeak: false, textSize: "normal" };
}

export function defaultLearning() {
  const now = new Date().toISOString();
  return {
    schemaVersion: LEARNING_SCHEMA_VERSION,
    createdAt: now,
    updatedAt: now,
    readArticles: {},
    bookmarks: [],
    highlights: [],
    quizScores: {},
    badges: [],
    streak: { count: 0, lastActiveDay: "", graceUsedOn: "" },
    calculatorRuns: {},
    activity: {}
  };
}

export function loadPreferences() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) {
      return defaultPreferences();
    }
    const parsed = JSON.parse(raw);
    return {
      theme: ["light", "dark"].includes(parsed.theme) ? parsed.theme : defaultPreferences().theme,
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
  if (dbPromise) {
    return dbPromise;
  }
  dbPromise = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB is unavailable in this browser."));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open local storage."));
    request.onblocked = () => reject(new Error("Local storage is blocked by another open tab."));
  });
  dbPromise.catch(() => {
    dbPromise = null;
  });
  return dbPromise;
}

export async function loadLearning() {
  try {
    const db = await openDatabase();
    const stored = await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(LEARNING_KEY);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    if (!stored || typeof stored !== "object") {
      return { learning: defaultLearning(), persisted: true };
    }
    return { learning: migrateLearning(stored), persisted: true };
  } catch {
    return { learning: defaultLearning(), persisted: false };
  }
}

// Migrations for historical schemas would branch here. A record that cannot
// be migrated is left alone and a fresh state is used instead, so the stored
// data is never destroyed by a failed migration.
function migrateLearning(stored) {
  if (stored.schemaVersion !== LEARNING_SCHEMA_VERSION) {
    return defaultLearning();
  }
  const base = defaultLearning();
  return {
    ...base,
    ...stored,
    createdAt: stored.createdAt || base.createdAt,
    streak: { ...base.streak, ...(stored.streak || {}) }
  };
}

export async function persistLearning(learning) {
  const record = { ...learning, updatedAt: new Date().toISOString() };
  const db = await openDatabase();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(record, LEARNING_KEY);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error || new Error("Save failed."));
    tx.onabort = () => reject(tx.error || new Error("Save was interrupted, possibly by low storage space."));
  });
  return record;
}

// Debounced autosave. Saves settle 600ms after the last change; failures
// surface through the callback so the interface can suggest exporting a
// backup before the browser clears anything.
export function createAutosaver(onError) {
  let timer = null;
  let pending = null;
  const flush = async () => {
    const snapshot = pending;
    pending = null;
    try {
      await persistLearning(snapshot);
    } catch (error) {
      if (typeof onError === "function") {
        onError(error);
      }
    }
  };
  return {
    queue(learning) {
      pending = learning;
      if (timer) {
        clearTimeout(timer);
      }
      timer = setTimeout(flush, 600);
    },
    async flushNow() {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (pending) {
        await flush();
      }
    }
  };
}
