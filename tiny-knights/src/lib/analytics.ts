/**
 * GoatCounter analytics — free, cookie-less, no personal data collected,
 * so no consent banner is needed and it's appropriate for a kids' site.
 *
 * Setup: create an account at https://www.goatcounter.com (pick a site code,
 * e.g. "tiny-knights"), then set GOATCOUNTER_CODE below. Empty string keeps
 * analytics fully disabled — no script is ever loaded.
 */
export const GOATCOUNTER_CODE = ''; // TODO: set after signing up at goatcounter.com

type GoatCounter = {
  no_onload?: boolean;
  count?: (opts: { path: string; title?: string; event?: boolean }) => void;
};

let initialized = false;

export function initAnalytics(): void {
  if (!GOATCOUNTER_CODE || initialized || typeof document === 'undefined') return;
  initialized = true;
  // We count screen changes ourselves, so disable the automatic page-load count
  (window as unknown as { goatcounter?: GoatCounter }).goatcounter = { no_onload: true };
  const script = document.createElement('script');
  script.async = true;
  script.src = 'https://gc.zgo.at/count.js';
  script.dataset.goatcounter = `https://${GOATCOUNTER_CODE}.goatcounter.com/count`;
  document.head.appendChild(script);
}

function goatcounter(): GoatCounter | undefined {
  return (window as unknown as { goatcounter?: GoatCounter }).goatcounter;
}

/** One "pageview" per screen the player visits (home, practice, victory...). */
export function trackScreen(screen: string): void {
  if (!GOATCOUNTER_CODE) return;
  goatcounter()?.count?.({ path: `/${screen}`, title: screen });
}

/** Named events for the moments that matter (e.g. Knight's Pass activation). */
export function trackEvent(name: string): void {
  if (!GOATCOUNTER_CODE) return;
  goatcounter()?.count?.({ path: name, title: name, event: true });
}
