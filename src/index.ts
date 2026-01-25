import { Hono } from "hono";
import { z } from "zod";
import { importJWK, SignJWT } from "jose";
import type { JWK } from "jose";

interface Env {
  ISSUER: string;
  ATTEST_PRIVATE_JWK: string;
  ATTEST_PUBLIC_JWK: string;
  POLICY_JSON?: string;
}

const KID = "bansou-key-1";
const ALLOWED_ALG = "EdDSA";
const THIRTY_DAYS_SEC = 30 * 24 * 60 * 60;

const app = new Hono<{ Bindings: Env }>();

// NOTE: CORS can be added later if needed.

const attestationSchema = z.object({
  sub: z.string().min(1),
  repo: z.string().regex(/^[^/]+\/[^/]+$/),
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  artifact: z.object({
    path: z.string().min(1),
    rangeStart: z.number().int().optional(),
    rangeEnd: z.number().int().optional()
  }),
  quiz_id: z.string().min(1),
  quiz_version: z.string().min(1),
  score: z.number().int().optional(),
  duration_ms: z.number().int().optional(),
  questions_hash: z.string().optional(),
  answers_hash: z.string().optional()
});

function isJwk(value: unknown): value is JWK {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.kty === "string";
}

function jsonError(c: any, status: number, code: string, message: string) {
  return c.json({ error: code, error_description: message }, status);
}

app.get("/.well-known/jwks.json", (c) => {
  const raw = c.env.ATTEST_PUBLIC_JWK;
  if (!raw) return jsonError(c, 500, "server_error", "ATTEST_PUBLIC_JWK is missing");
  let jwk: JWK;
  try {
    const parsed = JSON.parse(raw);
    if (!isJwk(parsed)) {
      return jsonError(c, 500, "server_error", "ATTEST_PUBLIC_JWK is missing required fields");
    }
    jwk = parsed;
  } catch {
    return jsonError(c, 500, "server_error", "ATTEST_PUBLIC_JWK is invalid JSON");
  }

  if (!jwk.kid) jwk.kid = KID;
  return c.json({ keys: [jwk] });
});

app.get("/policy", (c) => {
  const raw = c.env.POLICY_JSON;
  if (!raw) return c.json({});
  try {
    return c.json(JSON.parse(raw));
  } catch {
    return c.json({});
  }
});

app.post("/attestations/issue", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return jsonError(c, 400, "invalid_request", "Invalid JSON body");
  }

  const parsed = attestationSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(c, 400, "invalid_request", "Request validation failed");
  }

  const payload = parsed.data;

  if (payload.score !== undefined && payload.score < 80) {
    return jsonError(c, 403, "forbidden", "Score is below required minimum");
  }
  if (payload.duration_ms !== undefined && payload.duration_ms < 3000) {
    return jsonError(c, 403, "forbidden", "Duration is below required minimum");
  }

  const issuer = c.env.ISSUER;
  if (!issuer) return jsonError(c, 500, "server_error", "ISSUER is missing");

  const privateJwkRaw = c.env.ATTEST_PRIVATE_JWK;
  if (!privateJwkRaw) return jsonError(c, 500, "server_error", "ATTEST_PRIVATE_JWK is missing");

  let privateJwk: JWK;
  try {
    const parsed = JSON.parse(privateJwkRaw);
    if (!isJwk(parsed)) {
      return jsonError(c, 500, "server_error", "ATTEST_PRIVATE_JWK is missing required fields");
    }
    privateJwk = parsed;
  } catch {
    return jsonError(c, 500, "server_error", "ATTEST_PRIVATE_JWK is invalid JSON");
  }

  const key = await importJWK(privateJwk, ALLOWED_ALG);

  const now = Math.floor(Date.now() / 1000);
  const exp = now + THIRTY_DAYS_SEC;
  const nonce = crypto.randomUUID();

  const jwtPayload = {
    repo: payload.repo,
    commit: payload.commit,
    artifact: payload.artifact,
    quiz_id: payload.quiz_id,
    quiz_version: payload.quiz_version,
    score: payload.score ?? null,
    duration_ms: payload.duration_ms ?? null,
    questions_hash: payload.questions_hash ?? null,
    answers_hash: payload.answers_hash ?? null,
    nonce
  };

  const attestationJwt = await new SignJWT(jwtPayload)
    .setProtectedHeader({ alg: ALLOWED_ALG, kid: KID })
    .setIssuer(issuer)
    .setSubject(payload.sub)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key);

  return c.json({
    attestation_jwt: attestationJwt,
    commit: payload.commit,
    quiz_id: payload.quiz_id,
    exp
  });
});

export default app;
