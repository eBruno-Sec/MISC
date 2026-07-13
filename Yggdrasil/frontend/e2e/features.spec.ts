import { expect, test } from '@playwright/test'

const missions = [
  {
    id: 'alpha111',
    target: 'alpha.test',
    mode: 'passive',
    status: 'complete',
    current_phase: null,
    created_at: '2026-07-12T10:00:00Z',
    completed_at: '2026-07-12T10:05:00Z',
    severity_counts: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  },
  {
    id: 'beta2222',
    target: 'beta.test',
    mode: 'full',
    status: 'complete',
    current_phase: null,
    created_at: '2026-07-12T09:00:00Z',
    completed_at: '2026-07-12T09:10:00Z',
    severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  },
]

test.beforeEach(async ({ page }) => {
  await page.route('**/api/missions', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(missions),
  }))
  await page.route('**/api/missions/beta2222', route => {
    if (route.request().method() === 'DELETE') {
      return route.fulfill({ status: 200, contentType: 'application/json', body: '{"deleted":true}' })
    }
    return route.fallback()
  })
})

test('theme toggle persists across reloads', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /switch to light mode/i }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect.poll(() => page.evaluate(() => localStorage.getItem('yggdrasil_theme'))).toBe('light')

  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})

test('favorites pin, persist, and clean up on delete', async ({ page }) => {
  await page.goto('/')
  await page.getByTitle('Favorite').nth(1).click()
  await expect.poll(() => page.evaluate(() => localStorage.getItem('yggdrasil_favorites') || '')).toContain('beta2222')

  const text = await page.locator('main').innerText()
  expect(text.indexOf('beta.test')).toBeLessThan(text.indexOf('alpha.test'))

  page.on('dialog', dialog => dialog.accept())
  await page.getByTitle('Delete').first().click()
  await expect.poll(() => page.evaluate(() => localStorage.getItem('yggdrasil_favorites') || '')).not.toContain('beta2222')
})

test('workspace backup import label is present', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Import Workspace Backup (.json)' })).toBeVisible()
})

test('report toolbar theme and print hooks are wired', async ({ page }) => {
  await page.route('**/api/missions/report-test/report', route => route.fulfill({
    status: 200,
    contentType: 'text/html',
    body: `<!doctype html>
      <html><body>
        <button id="ygg-theme">Light</button>
        <button id="ygg-print">Print</button>
        <script>
          window.print = function(){ document.body.setAttribute('data-printed', 'true'); };
          var light = false;
          document.getElementById('ygg-theme').addEventListener('click', function(){
            light = !light;
            document.body.setAttribute('data-theme', light ? 'light' : '');
          });
          document.getElementById('ygg-print').addEventListener('click', function(){ window.print(); });
        </script>
      </body></html>`,
  }))

  await page.goto('/api/missions/report-test/report')
  await page.locator('#ygg-theme').click()
  await expect(page.locator('body')).toHaveAttribute('data-theme', 'light')
  await page.locator('#ygg-print').click()
  await expect(page.locator('body')).toHaveAttribute('data-printed', 'true')
})
