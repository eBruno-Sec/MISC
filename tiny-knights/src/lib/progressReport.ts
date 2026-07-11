import type { UserProgress } from '../types';
import { getFactsForTable, getOverallMasteryPercent, parseFactKey } from './facts';
import { getLevelFromXp } from './rewards';
import { getMasteryLabel } from './mastery';

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c] as string));
}

/**
 * Opens a print-ready progress report in a new window (Knight's Pass feature).
 * Self-contained HTML so it needs no app styles and survives being saved as PDF.
 */
export function openProgressReport(progress: UserProgress): void {
  const facts = Object.values(progress.facts);
  const mastered = facts.filter((f) => f.isMastered).length;
  const percent = getOverallMasteryPercent(progress.facts);
  const level = getLevelFromXp(progress.xp);

  const tableRows = Array.from({ length: progress.maxFactor }, (_, i) => i + 1)
    .map((t) => {
      const tf = getFactsForTable(progress.facts, t, progress.maxFactor);
      const done = tf.filter((f) => f.isMastered).length;
      const pct = tf.length ? Math.round((done / tf.length) * 100) : 0;
      return `<tr><td>${t}× table</td>
        <td><div class="bar"><div class="fill" style="width:${pct}%"></div></div></td>
        <td class="num">${done}/${tf.length}</td></tr>`;
    })
    .join('');

  const weak = facts
    .filter((f) => !f.isMastered && f.attempts > 0)
    .sort((a, b) => a.masteryLevel - b.masteryLevel || b.incorrect - a.incorrect)
    .slice(0, 10)
    .map((f) => {
      const { a, b } = parseFactKey(f.key);
      return `<span class="chip">${a} × ${b} <em>(${esc(getMasteryLabel(f.masteryLevel))})</em></span>`;
    })
    .join(' ');

  const html = `<!doctype html><html><head><meta charset="utf-8">
<title>Tiny Knights Progress Report — ${esc(progress.childName)}</title>
<style>
  body { font-family: 'Segoe UI', system-ui, sans-serif; color: #292524; margin: 40px; }
  h1 { color: #2845b8; margin-bottom: 0; }
  .sub { color: #b45309; font-weight: 600; margin-top: 4px; }
  .meta { color: #78716c; font-size: 14px; margin-top: 2px; }
  .stats { display: flex; gap: 16px; margin: 24px 0; flex-wrap: wrap; }
  .stat { border: 2px solid #e7e5e4; border-radius: 12px; padding: 12px 20px; text-align: center; }
  .stat b { display: block; font-size: 26px; color: #1c1917; }
  .stat span { font-size: 12px; color: #78716c; }
  table { border-collapse: collapse; width: 100%; margin-top: 8px; }
  td { padding: 6px 8px; font-size: 14px; }
  td.num { text-align: right; color: #78716c; white-space: nowrap; }
  .bar { background: #e7e5e4; border-radius: 99px; height: 12px; width: 100%; min-width: 200px; }
  .fill { background: #51cf66; border-radius: 99px; height: 12px; }
  .chip { display: inline-block; border: 1px solid #fecaca; background: #fef2f2; color: #b91c1c;
          border-radius: 99px; padding: 3px 10px; font-size: 13px; margin: 2px; }
  .chip em { color: #f87171; font-style: normal; font-size: 11px; }
  h2 { font-size: 16px; margin-top: 28px; }
  .cert { margin-top: 36px; border: 3px double #d6b24c; border-radius: 12px; padding: 16px 24px;
          text-align: center; color: #92400e; background: #fffbeb; }
  @media print { body { margin: 16px; } }
</style></head><body>
<h1>⚔️ Tiny Knights — Progress Report</h1>
<div class="sub">${esc(progress.childName)}</div>
<div class="meta">Generated ${new Date().toLocaleDateString()}</div>
<div class="stats">
  <div class="stat"><b>${percent}%</b><span>Overall mastery</span></div>
  <div class="stat"><b>${mastered}/${facts.length}</b><span>Facts mastered</span></div>
  <div class="stat"><b>Level ${level}</b><span>${progress.xp} XP</span></div>
  <div class="stat"><b>${progress.dailyStreak}</b><span>Day streak</span></div>
</div>
<h2>Mastery by table</h2>
<table>${tableRows}</table>
<h2>Facts that need practice</h2>
<div>${weak || '<span class="meta">None — great progress!</span>'}</div>
<div class="cert">🏅 Keep up the brave work, ${esc(progress.childName)}! Every quest makes you stronger.</div>
<script>window.onload = function () { window.print(); };</script>
</body></html>`;

  const win = window.open('', '_blank', 'width=820,height=1000');
  if (!win) return;
  win.document.write(html);
  win.document.close();
}
