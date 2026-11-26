import type { ErrorDetail } from "./types";

export const DEFAULT_API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/+$/, "");
export const API_PREFIX = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: ErrorDetail[];
  readonly requestId: string | null;
  readonly retryAfter: number | null;

  constructor(init: {
    status: number;
    code: string;
    message: string;
    details?: ErrorDetail[];
    requestId?: string | null;
    retryAfter?: number | null;
  }) {
    super(init.message);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.details = init.details ?? [];
    this.requestId = init.requestId ?? null;
    this.retryAfter = init.retryAfter ?? null;
  }

  /** A sentence a person can act on, built from the backend's own message. */
  get explanation(): string {
    if (this.status === 0) return this.message;
    if (this.code === "RATE_LIMITED" || this.status === 429) {
      return this.retryAfter
        ? `The API is rate limiting this browser. Try again in ${this.retryAfter} s.`
        : "The API is rate limiting this browser. Try again in a minute.";
    }
    if (this.code === "VALIDATION_ERROR" && this.details.length > 0) {
      const first = this.details[0];
      const field = first.field.replace(/^body\./, "").replaceAll("_", " ");
      return `${field}: ${first.message}`;
    }
    return this.message;
  }
}

type Session = { baseUrl: string; token: string | null };
const session: Session = { baseUrl: DEFAULT_API_BASE, token: null };
let unauthorizedHandler: (() => void) | null = null;

export function configureSession(next: Partial<Session>) {
  if (next.baseUrl !== undefined) session.baseUrl = next.baseUrl.replace(/\/+$/, "");
  if (next.token !== undefined) session.token = next.token;
}

export function currentBaseUrl() {
  return session.baseUrl;
}

export function onUnauthorized(handler: (() => void) | null) {
  unauthorizedHandler = handler;
}

type Query = Record<string, string | number | boolean | null | undefined>;

type RequestOptions = {
  query?: Query;
  body?: unknown;
  signal?: AbortSignal;
  /** Send this token instead of the session's (used to verify a token before saving it). */
  token?: string;
  /** Path is outside /api/v1 (only /health). */
  raw?: boolean;
  baseUrl?: string;
};

function buildUrl(base: string, path: string, query?: Query, raw?: boolean) {
  const url = new URL(`${base}${raw ? "" : API_PREFIX}${path}`);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

export async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const base = options.baseUrl ?? session.baseUrl;
  const token = options.token ?? session.token;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(buildUrl(base, path, options.query, options.raw), {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
      cache: "no-store",
    });
  } catch (error) {
    if ((error as Error).name === "AbortError") throw error;
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: `Can't reach the API at ${base}. Check that the backend is running and that CORS allows this origin.`,
    });
  }

  const requestId = response.headers.get("x-request-id");
  if (response.ok) {
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  let code = `HTTP_${response.status}`;
  let message = response.statusText || "Request failed";
  let details: ErrorDetail[] | undefined;
  try {
    const payload = (await response.json()) as { error?: { code?: string; message?: string; details?: ErrorDetail[] } };
    if (payload.error) {
      code = payload.error.code ?? code;
      message = payload.error.message ?? message;
      details = payload.error.details;
    }
  } catch {
    // Non-JSON error bodies keep the status text.
  }
  const retryHeader = response.headers.get("retry-after");
  const error = new ApiError({
    status: response.status,
    code,
    message,
    details,
    requestId,
    retryAfter: retryHeader ? Number.parseInt(retryHeader, 10) || null : null,
  });
  if (response.status === 401 && options.token === undefined) unauthorizedHandler?.();
  throw error;
}

/**
 * Opens a server-sent event stream with fetch, so the bearer token travels in the Authorization header
 * (EventSource can't set headers and tokens never go in URLs). Errors before the stream starts throw ApiError.
 */
export async function openStream(method: "GET" | "POST", path: string, options: RequestOptions = {}): Promise<Response> {
  const base = options.baseUrl ?? session.baseUrl;
  const headers: Record<string, string> = { Accept: "text/event-stream" };
  if (session.token) headers.Authorization = `Bearer ${session.token}`;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(buildUrl(base, path, options.query), {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
      cache: "no-store",
    });
  } catch (error) {
    if ((error as Error).name === "AbortError") throw error;
    throw new ApiError({
      status: 0,
      code: "NETWORK_ERROR",
      message: `Can't reach the API at ${base}. Check that the backend is running and that CORS allows this origin.`,
    });
  }
  if (response.ok && response.body) return response;
  let code = `HTTP_${response.status}`;
  let message = response.statusText || "Request failed";
  let details: ErrorDetail[] | undefined;
  try {
    const payload = (await response.json()) as { error?: { code?: string; message?: string; details?: ErrorDetail[] } };
    code = payload.error?.code ?? code;
    message = payload.error?.message ?? message;
    details = payload.error?.details;
  } catch {
    // Keep the status text.
  }
  const retryHeader = response.headers.get("retry-after");
  if (response.status === 401) unauthorizedHandler?.();
  throw new ApiError({
    status: response.status,
    code,
    message,
    details,
    requestId: response.headers.get("x-request-id"),
    retryAfter: retryHeader ? Number.parseInt(retryHeader, 10) || null : null,
  });
}

/** Reads SSE frames from a response body and hands each JSON payload to onEvent. */
export async function readEvents<T>(response: Response, onEvent: (event: T) => void): Promise<void> {
  const reader = response.body!.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value.replaceAll("\r\n", "\n");
    let index = buffer.indexOf("\n\n");
    while (index >= 0) {
      const frame = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      const data = frame
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice(5).trimStart())
        .join("\n");
      if (data && data !== "{}") {
        try {
          onEvent(JSON.parse(data) as T);
        } catch {
          // Ignore a malformed frame; the turn result is authoritative.
        }
      }
      index = buffer.indexOf("\n\n");
    }
  }
}

export const get = <T>(path: string, options?: RequestOptions) => request<T>("GET", path, options);
export const post = <T>(path: string, body?: unknown, options?: RequestOptions) =>
  request<T>("POST", path, { ...options, body: body ?? {} });
export const patch = <T>(path: string, body: unknown, options?: RequestOptions) =>
  request<T>("PATCH", path, { ...options, body });
export const del = <T>(path: string, options?: RequestOptions) => request<T>("DELETE", path, options);

export function isApiError(error: unknown): error is ApiError {
  return error instanceof ApiError;
}

export function describeError(error: unknown): string {
  if (isApiError(error)) return error.explanation;
  if (error instanceof Error) return error.message;
  return "Something went wrong";
}
