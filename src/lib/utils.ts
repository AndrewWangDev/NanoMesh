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
