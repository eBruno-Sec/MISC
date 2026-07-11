/** Local calendar date (not UTC) — a kid playing at 8pm should still count as "today". */
export function toLocalDateString(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

/**
 * Single source of truth for the daily streak. Any completed session counts:
 * same day keeps the streak, consecutive days extend it, a gap resets it to 1.
 */
export function advanceDailyStreak(
  lastPlayedDate: string | null,
  dailyStreak: number,
  now: Date = new Date()
): { dailyStreak: number; lastPlayedDate: string } {
  const today = toLocalDateString(now);
  // Older versions stored a full ISO timestamp; compare on the date part only.
  const lastDate = lastPlayedDate ? lastPlayedDate.slice(0, 10) : null;

  if (lastDate === today) {
    return { dailyStreak: Math.max(dailyStreak, 1), lastPlayedDate: today };
  }

  const yesterdayDate = new Date(now);
  yesterdayDate.setDate(yesterdayDate.getDate() - 1);
  const yesterday = toLocalDateString(yesterdayDate);

  return {
    dailyStreak: lastDate === yesterday ? dailyStreak + 1 : 1,
    lastPlayedDate: today,
  };
}
