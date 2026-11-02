const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const credentials = { email: 'admin@example.test', password: 'browser-test-password' };

async function login(page) {
  await page.goto('/login');
  await page.getByLabel('Email').fill(credentials.email);
  await page.getByLabel('Password').fill(credentials.password);
  await page.getByRole('button', { name: 'Sign In' }).click();
  await expect(page).toHaveURL(/\/$/);
}

async function expectAccessible(page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  expect(results.violations, results.violations.map(v => `${v.id}: ${v.help}`).join('\n')).toEqual([]);
}

test('login, mailbox navigation, draft autosave and settings', async ({ page }) => {
  await login(page);
  await page.getByRole('link', { name: 'Received mail' }).click();
  await expect(page.getByText('Browser fixture message')).toBeVisible();
  await page.getByRole('link', { name: /Open message: Browser fixture message/ }).press('Enter');
  await expect(page.getByRole('heading', { name: 'Browser fixture message' })).toBeVisible();

  await page.getByRole('link', { name: 'Compose' }).click();
  await page.getByRole('textbox', { name: 'To', exact: true }).fill('recipient@example.net');
  await page.getByLabel('Subject').fill('Browser draft');
  await page.getByPlaceholder('Write your message...').fill('Saved from Playwright');
  await page.getByRole('button', { name: 'Save draft' }).click();
  await expect(page.getByRole('status')).toHaveText('Draft saved');

  await page.getByTitle('Account settings').click();
  await page.getByLabel('Display name').fill('Browser Admin');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByRole('status')).toContainText('Settings saved.');
});

test('mobile navigation supports keyboard dismissal', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  await page.getByRole('button', { name: 'Toggle menu' }).click();
  await expect(page.locator('#sidebar')).toHaveClass(/open/);
  await page.keyboard.press('Escape');
  await expect(page.locator('#sidebar')).not.toHaveClass(/open/);
});

test('core pages have no axe WCAG violations', async ({ page }) => {
  await page.goto('/login');
  await expectAccessible(page);
  await login(page);
  for (const path of ['/inbox', '/compose', '/settings', '/admin', '/admin/backups']) {
    await page.goto(path);
    await expect(page, `failed to load ${path}`).not.toHaveURL(/\/login$/);
    await expectAccessible(page);
  }
});

test('queue controls, retention settings and outbound policy work in the browser', async ({ page }, testInfo) => {
  await login(page);
  const browser = testInfo.project.name;
  await page.goto('/admin/queue');
  await expect(page.getByRole('heading', { name: 'Outbound Queue' })).toBeVisible();
  await page.getByLabel('Sender or recipient').fill(`failed-${browser}@browser.invalid`);
  await page.getByRole('button', { name: 'Filter' }).click();
  const failedRow = page.locator('tr').filter({ hasText: `failed-${browser}@browser.invalid` });
  await expect(failedRow).toBeVisible();
  await failedRow.getByRole('link', { name: 'History' }).click();
  await expect(page.getByRole('heading', { name: /Delivery history for queue/ })).toBeVisible();
  await page.goto('/admin/queue');
  await page.locator('tr').filter({ hasText: `failed-${browser}@browser.invalid` }).getByRole('button', { name: 'Retry' }).click();
  await expect(page.getByRole('status')).toContainText('Updated 1');
  await page.locator('tr').filter({ hasText: `pending-${browser}@browser.invalid` }).getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('status')).toContainText('Updated 1');
  await page.getByLabel('Keep completed entries for days').fill('30');
  await page.getByRole('region', { name: 'Queue retention' }).getByRole('button', { name: 'Save' }).click();
  await expect(page.getByLabel('Keep completed entries for days')).toHaveValue('30');
  await page.getByLabel('Keep archived mappings for days').fill('90');
  await page.getByRole('region', { name: 'Archived VERP retention' }).getByRole('button', { name: 'Save' }).click();
  await expect(page.getByLabel('Keep archived mappings for days')).toHaveValue('90');
  await page.goto('/admin/outbound-limits');
  await expect(page.getByRole('heading', { name: 'Outbound Account Limits' })).toBeVisible();
  await page.getByLabel('Messages per hour').fill('110');
  await page.getByRole('button', { name: 'Save and apply' }).click();
  await expect(page.getByLabel('Messages per hour')).toHaveValue('110');
});

test('admin operational pages are accessible at mobile width', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page);
  for (const path of ['/admin/queue', '/admin/outbound-limits']) {
    await page.goto(path);
    await expectAccessible(page);
  }
});
