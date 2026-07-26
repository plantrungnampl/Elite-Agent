import { expect, test, type Page } from "@playwright/test";

test("first Tab reaches the skip link and activation moves focus to main", async ({
  page,
}) => {
  await openShell(page);

  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("link", { name: "Skip to startup status" }),
  ).toBeFocused();

  await page.keyboard.press("Enter");
  await expect(page.getByRole("main")).toBeFocused();

  await page.keyboard.press("Tab");
  const summary = page.getByText("Local diagnostics (0)");
  await expect(summary).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(summary.locator("..")).toHaveJSProperty("open", true);
});

test("reduced motion and narrow reflow stay usable", async ({ browser }) => {
  const context = await browser.newContext({
    reducedMotion: "reduce",
    viewport: { width: 640, height: 720 },
  });
  const page = await context.newPage();
  await openShell(page);

  const durations = await page.getByRole("status").evaluate((element) => {
    const style = getComputedStyle(element);
    return [style.animationDuration, style.transitionDuration];
  });
  expect(Math.max(...durations.map(maxTimeMs))).toBeLessThanOrEqual(0.1);

  // 640 CSS px models 200% zoom on a 1280 px-wide desktop viewport.
  for (const width of [640, 320]) {
    await page.setViewportSize({ width, height: 720 });
    await page.reload();
    await expect(
      page.getByRole("heading", { level: 1, name: "Startup health" }),
    ).toBeVisible();
    await expect(page.getByRole("status")).toBeVisible();
    const summary = page.getByText("Local diagnostics (0)");
    await expect(summary).toBeVisible();
    await summary.click();
    await expect(summary.locator("..")).toHaveJSProperty("open", true);

    const overflow = await page.evaluate(() => ({
      client: document.documentElement.clientWidth,
      scroll: document.documentElement.scrollWidth,
    }));
    expect(overflow.scroll).toBeLessThanOrEqual(overflow.client);
  }

  await context.close();
});

async function openShell(page: Page) {
  await page.addInitScript(() => {
    (
      window as typeof window & {
        __TAURI_INTERNALS__: { invoke: () => Promise<never> };
      }
    ).__TAURI_INTERNALS__ = {
      invoke: () => Promise.reject(new Error("Tauri IPC is unavailable")),
    };
  });
  await page.goto("/");
}

function maxTimeMs(value: string) {
  return Math.max(
    ...value.split(",").map((duration) => {
      const trimmed = duration.trim();
      const amount = Number.parseFloat(trimmed);
      return trimmed.endsWith("ms") ? amount : amount * 1_000;
    }),
  );
}
