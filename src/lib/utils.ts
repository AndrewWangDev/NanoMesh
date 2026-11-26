/**
 * Utility functions for NanoMesh Frontend & Gateway
 */

/**
 * Safely parses a JSON request body, preventing unhandled TypeError when request body
 * evaluates to JSON literal `null`, primitive types (`123`, `true`, `"string"`), or invalid JSON.
 * Returns an empty plain object `{}` if parsing fails or if the result is not a non-array object.
 */
export async function safeJsonBody<T = any>(request: Request): Promise<T> {
  try {
    const raw = await request.json();
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      return raw as T;
    }
    return {} as T;
  } catch {
    return {} as T;
  }
}

/**
 * Safely parses a positive/bounded integer query parameter, guarding against NaN
 * when inputs like "abc" or "NaN" are passed (which would break D1 LIMIT/OFFSET bindings).
 */
export function safeParseInt(
  raw: string | null | undefined,
  fallback: number,
  min?: number,
  max?: number
): number {
  if (!raw || typeof raw !== "string") return fallback;
  const parsed = parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  let result = parsed;
  if (min !== undefined) result = Math.max(min, result);
  if (max !== undefined) result = Math.min(max, result);
  return result;
}
