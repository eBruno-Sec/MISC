import type { FactState } from '../types';

export function getHintForFact(fact: FactState): string {
  const { a, b } = fact;
  const small = Math.min(a, b);
  const big = Math.max(a, b);

  if (small === 1) return `Anything times 1 stays the same. ${big} × 1 = ${big}.`;
  if (small === 0 || big === 0) return `Anything times 0 is 0.`;
  if (small === 2 || big === 2) {
    const other = small === 2 ? big : small;
    return `Doubling! ${other} + ${other} = ${other * 2}.`;
  }
  if (small === 5 || big === 5) {
    const other = small === 5 ? big : small;
    return `Count by 5s ${other} times, like a clock: 5, 10, 15...`;
  }
  if (small === 9 || big === 9) {
    const other = small === 9 ? big : small;
    return `Try 10 × ${other} minus ${other}.`;
  }
  if (small === 4 || big === 4) {
    const other = small === 4 ? big : small;
    return `Double it, then double again: ${other} → ${other * 2} → ${other * 4}.`;
  }
  if (small === 6 || big === 6) {
    const other = small === 6 ? big : small;
    return `Use 5 × ${other} plus one more group of ${other}.`;
  }
  if (small === 8 || big === 8) {
    const other = small === 8 ? big : small;
    return `Double, double, double: ${other} → ${other * 2} → ${other * 4} → ${other * 8}.`;
  }
  if (small === 3 || big === 3) {
    const other = small === 3 ? big : small;
    return `Add ${other} three times: ${other} + ${other} + ${other}.`;
  }
  if (small === 7 || big === 7) {
    const other = small === 7 ? big : small;
    return `Try 5 × ${other} plus 2 × ${other}.`;
  }

  return `Remember: ${a} × ${b} is the same as ${b} × ${a}.`;
}

export function getCommutativeHint(a: number, b: number): string {
  return `${a} × ${b} is the same as ${b} × ${a}.`;
}

/**
 * Generate plausible wrong-answer choices for multiple choice mode.
 */
export function generateMultipleChoiceOptions(correctAnswer: number, a: number, b: number): number[] {
  const options = new Set<number>([correctAnswer]);

  const candidates = [
    correctAnswer + a,
    correctAnswer - a,
    correctAnswer + b,
    correctAnswer - b,
    a * (b + 1),
    a * (b - 1),
    correctAnswer + 1,
    correctAnswer - 1,
    correctAnswer + 10,
    correctAnswer - 10,
  ].filter((n) => n > 0 && n !== correctAnswer);

  // shuffle candidates
  for (let i = candidates.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
  }

  for (const c of candidates) {
    if (options.size >= 4) break;
    options.add(c);
  }

  // fallback fill if not enough unique distractors
  let fallback = correctAnswer + 2;
  while (options.size < 4) {
    if (fallback > 0 && !options.has(fallback)) options.add(fallback);
    fallback += 1;
  }

  const arr = Array.from(options);
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
