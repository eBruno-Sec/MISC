/**
 * Tiny WebAudio sound effects — no audio assets, just oscillators.
 * All triggers originate from user taps, so the AudioContext is
 * allowed to start by browser autoplay policies.
 */
export type SfxName = 'tap' | 'correct' | 'incorrect' | 'monsterDown' | 'victory';

let audioCtx: AudioContext | null = null;
let enabled = true;

export function setSoundEnabled(value: boolean): void {
  enabled = value;
}

function getContext(): AudioContext | null {
  if (typeof window === 'undefined') return null;
  const Ctor =
    window.AudioContext ??
    (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
  if (!Ctor) return null;
  if (!audioCtx) {
    try {
      audioCtx = new Ctor();
    } catch {
      return null;
    }
  }
  if (audioCtx.state === 'suspended') void audioCtx.resume();
  return audioCtx;
}

function tone(
  ctx: AudioContext,
  freq: number,
  at: number,
  duration: number,
  type: OscillatorType = 'triangle',
  peak = 0.1
): void {
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = type;
  osc.frequency.setValueAtTime(freq, at);
  gain.gain.setValueAtTime(0.0001, at);
  gain.gain.exponentialRampToValueAtTime(peak, at + 0.015);
  gain.gain.exponentialRampToValueAtTime(0.0001, at + duration);
  osc.connect(gain);
  gain.connect(ctx.destination);
  osc.start(at);
  osc.stop(at + duration + 0.05);
}

export function playSfx(name: SfxName): void {
  if (!enabled) return;
  const ctx = getContext();
  if (!ctx) return;
  const t = ctx.currentTime;

  switch (name) {
    case 'tap':
      tone(ctx, 520, t, 0.05, 'square', 0.025);
      break;
    case 'correct':
      // rising C–E–G arpeggio
      tone(ctx, 523.25, t, 0.1);
      tone(ctx, 659.25, t + 0.07, 0.1);
      tone(ctx, 783.99, t + 0.14, 0.16);
      break;
    case 'incorrect':
      // gentle low two-tone, deliberately non-punishing
      tone(ctx, 233.08, t, 0.18, 'sine', 0.06);
      tone(ctx, 207.65, t + 0.12, 0.22, 'sine', 0.05);
      break;
    case 'monsterDown':
      tone(ctx, 392, t, 0.08, 'square', 0.05);
      tone(ctx, 523.25, t + 0.06, 0.08, 'square', 0.05);
      tone(ctx, 659.25, t + 0.12, 0.08, 'square', 0.05);
      tone(ctx, 1046.5, t + 0.18, 0.2);
      break;
    case 'victory':
      [523.25, 659.25, 783.99, 1046.5].forEach((f, i) => tone(ctx, f, t + i * 0.12, 0.22));
      tone(ctx, 1318.51, t + 0.5, 0.4, 'triangle', 0.11);
      break;
  }
}
