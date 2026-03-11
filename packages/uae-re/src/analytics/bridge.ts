/**
 * Python Subprocess Bridge
 *
 * Executes Python analytics scripts via subprocess with JSON stdin/stdout I/O,
 * timeout enforcement, and comprehensive error handling.
 */

import { spawn } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { PythonResult, PythonScriptName, BridgeConfig } from "./types.js";

// Resolve the path to the Python package directory
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DEFAULT_PYTHON_PKG_DIR = resolve(__dirname, "../../python");

/**
 * Default bridge configuration.
 */
const DEFAULT_CONFIG: BridgeConfig = {
  venvPath: "/opt/lobsec/analytics-venv",
  pythonPkgDir: DEFAULT_PYTHON_PKG_DIR,
  defaultTimeoutMs: 30_000,
};

/**
 * Execute a Python analytics script with JSON I/O.
 *
 * @param scriptName - Name of the Python module to execute (in uae_re package)
 * @param input - Input data to send as JSON to stdin
 * @param config - Optional bridge configuration overrides
 * @returns Promise resolving to PythonResult with parsed output or error
 */
export async function runPython<T>(
  scriptName: PythonScriptName,
  input: unknown,
  config?: Partial<BridgeConfig>
): Promise<PythonResult<T>> {
  const fullConfig: BridgeConfig = { ...DEFAULT_CONFIG, ...config };
  const startTime = Date.now();

  const pythonExe = resolve(fullConfig.venvPath, "bin/python3");
  const args = ["-m", `uae_re.${scriptName}`];

  let stdout = "";
  let stderr = "";
  let exitCode: number | undefined;
  let timeoutHandle: NodeJS.Timeout | undefined;

  return new Promise((resolve) => {
    const proc = spawn(pythonExe, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: {
        ...process.env,
        PYTHONPATH: fullConfig.pythonPkgDir,
      },
      cwd: fullConfig.pythonPkgDir,
    });

    // Set up timeout
    timeoutHandle = setTimeout(() => {
      const durationMs = Date.now() - startTime;

      // Try graceful termination first
      proc.kill("SIGTERM");

      // Force kill after 5 seconds if still alive
      setTimeout(() => {
        if (proc.exitCode === null) {
          proc.kill("SIGKILL");
        }
      }, 5_000);

      resolve({
        success: false,
        error: `Timeout after ${fullConfig.defaultTimeoutMs}ms`,
        stderr,
        durationMs,
      });
    }, fullConfig.defaultTimeoutMs);

    // Collect stdout
    proc.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    // Collect stderr
    proc.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    // Handle process completion
    proc.on("close", (code) => {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }

      exitCode = code ?? undefined;
      const durationMs = Date.now() - startTime;

      // Check for non-zero exit code
      if (code !== 0) {
        resolve({
          success: false,
          error: stderr || `Exit code ${code}`,
          exitCode: code ?? undefined,
          stderr,
          durationMs,
        });
        return;
      }

      // Try to parse JSON output
      try {
        const data = JSON.parse(stdout) as T;
        resolve({
          success: true,
          data,
          stderr,
          durationMs,
        });
      } catch (parseError) {
        const errorMsg =
          parseError instanceof Error
            ? parseError.message
            : String(parseError);
        resolve({
          success: false,
          error: `JSON parse error: ${errorMsg}`,
          stderr,
          durationMs,
        });
      }
    });

    // Handle process errors
    proc.on("error", (err) => {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }

      const durationMs = Date.now() - startTime;
      resolve({
        success: false,
        error: `Process error: ${err.message}`,
        stderr,
        durationMs,
      });
    });

    // Write input to stdin
    try {
      const inputJson = JSON.stringify(input);
      proc.stdin?.write(inputJson);
      proc.stdin?.end();
    } catch (err) {
      if (timeoutHandle) {
        clearTimeout(timeoutHandle);
      }

      const durationMs = Date.now() - startTime;
      const errorMsg = err instanceof Error ? err.message : String(err);
      resolve({
        success: false,
        error: `Failed to write input: ${errorMsg}`,
        stderr,
        durationMs,
      });
    }
  });
}

/**
 * Check if Python is available in the configured venv.
 *
 * @param config - Optional bridge configuration overrides
 * @returns Promise with availability status and version
 */
export async function checkPythonAvailable(
  config?: Partial<BridgeConfig>
): Promise<{ available: boolean; version?: string; error?: string }> {
  const fullConfig: BridgeConfig = { ...DEFAULT_CONFIG, ...config };
  const pythonExe = resolve(fullConfig.venvPath, "bin/python3");

  return new Promise((resolve) => {
    const proc = spawn(pythonExe, ["--version"], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let output = "";

    proc.stdout?.on("data", (chunk) => {
      output += chunk.toString();
    });

    proc.stderr?.on("data", (chunk) => {
      output += chunk.toString();
    });

    proc.on("close", (code) => {
      if (code === 0) {
        resolve({ available: true, version: output.trim() });
      } else {
        resolve({
          available: false,
          error: `Python check failed with exit code ${code}`,
        });
      }
    });

    proc.on("error", (err) => {
      resolve({ available: false, error: err.message });
    });
  });
}

/**
 * Check if all required Python dependencies are available.
 *
 * @param config - Optional bridge configuration overrides
 * @returns Promise with dependency check results
 */
export async function checkDependencies(
  config?: Partial<BridgeConfig>
): Promise<{ available: boolean; missing: string[]; error?: string }> {
  const fullConfig: BridgeConfig = { ...DEFAULT_CONFIG, ...config };
  const pythonExe = resolve(fullConfig.venvPath, "bin/python3");

  const importScript = `
import sys
missing = []
packages = [
    'pandas',
    'statsmodels',
    'scipy',
    'numpy',
    'pdfplumber',
    'vaderSentiment',
    'praw',
    'pytrends'
]
for pkg in packages:
    try:
        __import__(pkg)
    except ImportError:
        missing.append(pkg)

if missing:
    print(','.join(missing))
    sys.exit(1)
else:
    print('ok')
    sys.exit(0)
`;

  return new Promise((resolve) => {
    const proc = spawn(pythonExe, ["-c", importScript], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    proc.stdout?.on("data", (chunk) => {
      stdout += chunk.toString();
    });

    proc.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      if (code === 0) {
        resolve({ available: true, missing: [] });
      } else {
        const missing = stdout
          .trim()
          .split(",")
          .filter((s) => s.length > 0);
        resolve({ available: false, missing, error: stderr || undefined });
      }
    });

    proc.on("error", (err) => {
      resolve({ available: false, missing: [], error: err.message });
    });
  });
}
