import type { Badge } from '../types';

export const BADGE_DEFINITIONS: Omit<Badge, 'earnedAt'>[] = [
  { id: 'badge-1s-hero', name: '1s Hero', description: 'Mastered all 1× facts', icon: '🌿' },
  { id: 'badge-2s-hero', name: '2s Hero', description: 'Mastered all 2× facts', icon: '🌳' },
  { id: 'badge-3s-hero', name: '3s Hero', description: 'Mastered all 3× facts', icon: '🪨' },
  { id: 'badge-4s-hero', name: '4s Hero', description: 'Mastered all 4× facts', icon: '🧱' },
  { id: 'badge-5s-clock-master', name: '5s Clock Master', description: 'Mastered all 5× facts', icon: '🕐' },
  { id: 'badge-6s-hero', name: '6s Hero', description: 'Mastered all 6× facts', icon: '⚙️' },
  { id: 'badge-7s-dragon-tamer', name: '7s Dragon Tamer', description: 'Mastered all 7× facts', icon: '🐉' },
  { id: 'badge-8s-hero', name: '8s Hero', description: 'Mastered all 8× facts', icon: '💎' },
  { id: 'badge-9s-ninja', name: '9s Ninja', description: 'Mastered all 9× facts', icon: '🥷' },
  { id: 'badge-10s-hero', name: '10s Hero', description: 'Mastered all 10× facts', icon: '🏰' },
  { id: 'badge-11s-hero', name: '11s Hero', description: 'Mastered all 11× facts', icon: '🏆' },
  { id: 'badge-12s-hero', name: '12s Hero', description: 'Mastered all 12× facts', icon: '⭐' },
  { id: 'badge-no-mistake', name: 'No Mistake Round', description: 'Completed a quest with zero mistakes', icon: '✨' },
  { id: 'badge-comeback', name: 'Comeback Champ', description: 'Mastered a fact you once struggled with', icon: '💪' },
  { id: 'badge-7-day-streak', name: '7-Day Streak', description: 'Played 7 days in a row', icon: '🔥' },
  { id: 'badge-boss-slayer', name: 'Boss Slayer', description: 'Won your first Boss Battle', icon: '⚔️' },
  { id: 'badge-all-tables', name: 'All Tables Explorer', description: 'Practiced every table at least once', icon: '🗺️' },
];

export function createDefaultBadges(): Badge[] {
  return BADGE_DEFINITIONS.map((b) => ({ ...b, earnedAt: null }));
}
