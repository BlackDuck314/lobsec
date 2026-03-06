import type { Page } from "playwright";
import { PNG } from "pngjs";
import pixelmatch from "pixelmatch";
import {
  readFileSync,
  writeFileSync,
  copyFileSync,
  mkdirSync,
  existsSync,
} from "node:fs";

// Types
export interface VisualCheckpoint {
  name: string;
  description: string; // Human-readable for issue bodies
}

export interface VisualCheckResult {
  name: string;
  passed: boolean;
  isNewBaseline: boolean;
  diffPixels: number;
  diffPercent: number;
  diffPath?: string; // Path to diff image (only when failed)
  currentPath: string; // Path to current screenshot
  baselinePath: string; // Path to baseline
  error?: string; // Dimension mismatch etc.
}

// Constants
export const VISUAL_CHECKPOINTS: VisualCheckpoint[] = [
  { name: "login-page", description: "Login form page (before credentials)" },
  { name: "dashboard", description: "Dashboard after successful login" },
  { name: "study-start", description: "Study session start page" },
];

const SCREENSHOT_DIR = "/opt/lobsec/logs/examy";
const BASELINE_DIR = `${SCREENSHOT_DIR}/baselines`;
const DIFF_THRESHOLD_PERCENT = 5; // User requirement: 5% pixel difference threshold
const PIXELMATCH_THRESHOLD = 0.1; // Anti-aliasing sensitivity (0-1)

/**
 * Capture a screenshot at a visual checkpoint
 * @param page Playwright page instance
 * @param checkpointName Name of the checkpoint (from VISUAL_CHECKPOINTS)
 * @returns Path to the captured screenshot
 */
async function captureCheckpointScreenshot(
  page: Page,
  checkpointName: string
): Promise<string> {
  // Set consistent viewport for reproducible screenshots
  await page.setViewportSize({ width: 1280, height: 720 });

  // Wait for animations to settle
  await new Promise((resolve) => setTimeout(resolve, 1000));

  const screenshotPath = `${SCREENSHOT_DIR}/${checkpointName}-current.png`;

  // Mask password field on login page
  if (checkpointName === "login-page") {
    await page.screenshot({
      path: screenshotPath,
      fullPage: true,
      mask: [page.locator('input[type="password"]')],
    });
  } else {
    await page.screenshot({
      path: screenshotPath,
      fullPage: true,
    });
  }

  return screenshotPath;
}

/**
 * Compare two screenshots using pixelmatch
 * @param baselinePath Path to baseline screenshot
 * @param currentPath Path to current screenshot
 * @param diffPath Path to save diff image
 * @param thresholdPercent Percentage threshold for regression flagging
 * @returns Comparison result
 */
function compareScreenshot(
  baselinePath: string,
  currentPath: string,
  diffPath: string,
  thresholdPercent: number
): {
  passed: boolean;
  diffPixels: number;
  diffPercent: number;
  diffPath?: string;
  error?: string;
} {
  // Read both PNGs
  const baseline = PNG.sync.read(readFileSync(baselinePath));
  const current = PNG.sync.read(readFileSync(currentPath));

  // Check dimension match
  if (
    baseline.width !== current.width ||
    baseline.height !== current.height
  ) {
    return {
      passed: false,
      diffPixels: 0,
      diffPercent: 0,
      error: `Dimensions mismatch: baseline ${baseline.width}x${baseline.height} vs current ${current.width}x${current.height}`,
    };
  }

  const { width, height } = current;
  const diff = new PNG({ width, height });

  // Run pixel comparison
  const diffPixels = pixelmatch(
    current.data,
    baseline.data,
    diff.data,
    width,
    height,
    { threshold: PIXELMATCH_THRESHOLD }
  );

  const totalPixels = width * height;
  const diffPercent = (diffPixels / totalPixels) * 100;

  // Save diff image if threshold exceeded
  if (diffPercent > thresholdPercent) {
    writeFileSync(diffPath, PNG.sync.write(diff));
    return {
      passed: false,
      diffPixels,
      diffPercent,
      diffPath,
    };
  }

  return {
    passed: true,
    diffPixels,
    diffPercent,
  };
}

/**
 * Compare visual baselines for all checkpoints
 * @param page Playwright page instance
 * @param updateBaselines If true, update baselines instead of comparing
 * @returns Array of visual check results
 */
export async function compareVisualBaselines(
  page: Page,
  updateBaselines: boolean = false
): Promise<VisualCheckResult[]> {
  const results: VisualCheckResult[] = [];

  // Set viewport once at the start
  await page.setViewportSize({ width: 1280, height: 720 });

  for (const checkpoint of VISUAL_CHECKPOINTS) {
    const currentPath = await captureCheckpointScreenshot(
      page,
      checkpoint.name
    );
    const baselinePath = `${BASELINE_DIR}/${checkpoint.name}.png`;
    const diffPath = `${SCREENSHOT_DIR}/${checkpoint.name}-diff.png`;

    // Create baseline if it doesn't exist OR if updateBaselines is true
    if (!existsSync(baselinePath) || updateBaselines) {
      // Create baseline directory
      mkdirSync(BASELINE_DIR, { recursive: true });

      // Copy current to baseline
      copyFileSync(currentPath, baselinePath);

      results.push({
        name: checkpoint.name,
        passed: true,
        isNewBaseline: true,
        diffPixels: 0,
        diffPercent: 0,
        currentPath,
        baselinePath,
      });
      continue;
    }

    // Compare with baseline
    const comparison = compareScreenshot(
      baselinePath,
      currentPath,
      diffPath,
      DIFF_THRESHOLD_PERCENT
    );

    results.push({
      name: checkpoint.name,
      passed: comparison.passed,
      isNewBaseline: false,
      diffPixels: comparison.diffPixels,
      diffPercent: comparison.diffPercent,
      diffPath: comparison.diffPath,
      currentPath,
      baselinePath,
      error: comparison.error,
    });
  }

  return results;
}
