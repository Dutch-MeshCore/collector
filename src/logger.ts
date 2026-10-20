/**
 * Minimal leveled logger. LOG_LEVEL=debug|info|warn|error.
 *
 * Unset (or invalid) means "debug", i.e. everything is logged, which is the
 * behaviour before this helper existed. Errors (console.error) are never
 * filtered. The level is read lazily on first use so that a LOG_LEVEL coming
 * from the .env file (loaded by dotenv in config.ts) is honoured regardless of
 * module evaluation order.
 */
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type Level = keyof typeof LEVELS;

let threshold: number | undefined;

function getThreshold(): number {
  if (threshold === undefined) {
    const raw = (process.env.LOG_LEVEL || '').trim().toLowerCase();
    if (raw && !(raw in LEVELS)) {
      console.warn(`[CONFIG] Invalid LOG_LEVEL "${raw}", falling back to debug (log everything)`);
    }
    threshold = raw in LEVELS ? LEVELS[raw as Level] : LEVELS.debug;
  }
  return threshold;
}

/** Per-connection / per-publish chatter and credential-bearing lines. */
export function logDebug(...args: unknown[]): void {
  if (getThreshold() <= LEVELS.debug) console.log(...args);
}

/** Normal operational lines, denials, disconnect reasons, abuse events. */
export function logInfo(...args: unknown[]): void {
  if (getThreshold() <= LEVELS.info) console.log(...args);
}

export function logWarn(...args: unknown[]): void {
  if (getThreshold() <= LEVELS.warn) console.warn(...args);
}
