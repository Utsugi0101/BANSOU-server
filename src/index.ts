import { Hono } from 'hono';
import { z } from 'zod';
import { importJWK, jwtVerify, SignJWT } from 'jose';
import type { JWK, JWTPayload } from 'jose';

interface Env {
  ISSUER: string;
  ATTEST_PRIVATE_JWK: string;
  ATTEST_PUBLIC_JWK: string;
  OPENAI_API_KEY?: string;
  GATE_API_TOKEN?: string;
  ATTEST_DB?: D1Database;
  POLICY_JSON?: string;
}

const KID = 'bansou-key-1';
const ALLOWED_ALG = 'EdDSA';
const THIRTY_DAYS_SEC = 30 * 24 * 60 * 60;
const QUIZ_SESSION_TTL_SEC = 30 * 60;
const MIN_SCORE = 80;
const MIN_DURATION_MS = 3000;
type JoseKey = Awaited<ReturnType<typeof importJWK>>;

const app = new Hono<{ Bindings: Env }>();

type Artifact = {
  path: string;
  rangeStart?: number;
  rangeEnd?: number;
};

type QuizQuestionInternal = {
  filePath: string;
  question: string;
  options: [string, string, string, string];
  answerIndex: number;
  rationale: string;
  hunkSummary: string;
};

type QuizQuestionPublic = Omit<QuizQuestionInternal, 'answerIndex'>;

type QuizSessionPayload = {
  repo: string;
  commit: string;
  quiz_id: string;
  quiz_version: string;
  questions: QuizQuestionInternal[];
  artifacts: Artifact[];
  questions_hash: string;
  diff_hash: string;
  nonce: string;
};

const attestationSchema = z.object({
  sub: z.string().min(1),
  repo: z.string().regex(/^[^/]+\/[^/]+$/),
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  artifact: z.object({
    path: z.string().min(1),
    rangeStart: z.number().int().optional(),
    rangeEnd: z.number().int().optional(),
  }),
  quiz_id: z.string().min(1),
  quiz_version: z.string().min(1),
  score: z.number().int().optional(),
  duration_ms: z.number().int().optional(),
  questions_hash: z.string().optional(),
  answers_hash: z.string().optional(),
  diff_hash: z.string().optional(),
});

const quizGenerateSchema = z.object({
  sub: z.string().min(1),
  repo: z.string().regex(/^[^/]+\/[^/]+$/),
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  quiz_id: z.string().default('core-pr'),
  quiz_version: z.string().default('1.0.0'),
  files: z.array(z.string().min(1)).min(1),
  diffsByFile: z.record(z.string()),
  desiredQuestionCount: z.number().int().min(1).max(20).optional(),
  artifacts: z
    .array(
      z.object({
        path: z.string().min(1),
        rangeStart: z.number().int().optional(),
        rangeEnd: z.number().int().optional(),
      })
    )
    .optional(),
});

const quizSubmitSchema = z.object({
  quiz_session_token: z.string().min(1),
  answers: z.array(z.number().int().min(0).max(3)),
  duration_ms: z.number().int().min(0).optional(),
});

const gateEvaluateSchema = z.object({
  repo: z.string().regex(/^[^/]+\/[^/]+$/),
  commit: z.string().regex(/^[0-9a-f]{40}$/),
  sub: z.string().min(1),
  required_quiz_id: z.string().min(1),
  changed_files: z.array(z.string().min(1)),
});

function isJwk(value: unknown): value is JWK {
  if (typeof value !== 'object' || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.kty === 'string';
}

function jsonError(c: any, status: number, code: string, message: string) {
  return c.json({ error: code, error_description: message }, status);
}

function normalizeText(input: string): string {
  return input.replace(/\r\n/g, '\n');
}

async function sha256Base64Url(input: string): Promise<string> {
  const encoded = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  const bytes = Array.from(new Uint8Array(digest));
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function computeDiffHash(diffsByFile: Record<string, string>): Promise<string> {
  const payload = Object.keys(diffsByFile)
    .sort()
    .map((filePath) => `${filePath}\n${normalizeText(diffsByFile[filePath] ?? '')}`)
    .join('\n');
  return sha256Base64Url(payload);
}

async function computeQuestionsHash(questions: QuizQuestionInternal[]): Promise<string> {
  return sha256BaseUrlFromJson(questions);
}

async function computeAnswersHash(answers: number[]): Promise<string> {
  return sha256BaseUrlFromJson(answers);
}

async function sha256BaseUrlFromJson(value: unknown): Promise<string> {
  return sha256Base64Url(JSON.stringify(value));
}

function summarizeDiff(diff: string): string {
  const lines = normalizeText(diff).split('\n');
  const added = lines.filter((line) => line.startsWith('+') && !line.startsWith('+++')).length;
  const removed = lines.filter((line) => line.startsWith('-') && !line.startsWith('---')).length;
  return `added:${added}, removed:${removed}`;
}

function buildTemplateQuestions(files: string[], diffsByFile: Record<string, string>, desiredCount: number): QuizQuestionInternal[] {
  const targets = files.slice(0, Math.max(1, desiredCount));
  return targets.map((filePath) => {
    const diff = diffsByFile[filePath] ?? '';
    const hunkSummary = summarizeDiff(diff);
    return {
      filePath,
      question: `${filePath} の変更レビューで最も重要な確認はどれですか？`,
      options: [
        '変更意図・挙動・影響範囲を具体的に説明できること',
        'ファイル名と雰囲気だけ把握すること',
        'テストせずそのままマージすること',
        'レビューコメントを後で読むこと',
      ],
      answerIndex: 0,
      rationale: '変更の理解を証明するには、意図・挙動・影響範囲を説明可能であることが必要です。',
      hunkSummary,
    };
  });
}

async function generateQuizQuestionsWithOpenAI(
  apiKey: string,
  files: string[],
  diffsByFile: Record<string, string>,
  desiredQuestionCount: number
): Promise<QuizQuestionInternal[]> {
  const systemPrompt =
    'あなたはgit diffに対する理解確認クイズを作成します。JSONのみ返し、説明文を外に出さないでください。';
  const userPrompt = [
    `desiredQuestionCount=${desiredQuestionCount}`,
    'rules:',
    '- 選択肢4つ',
    '- answerIndexは0-3',
    '- すべて日本語',
    '- filePathは与えられたfilesのいずれか',
    'files:',
    ...files,
    'diffs:',
    ...files.map((filePath) => `FILE:${filePath}\n${diffsByFile[filePath] ?? ''}`),
  ].join('\n');

  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'gpt-5-mini',
      input: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: userPrompt },
      ],
      text: {
        format: {
          type: 'json_schema',
          name: 'server_quiz_schema',
          strict: true,
          schema: {
            type: 'object',
            additionalProperties: false,
            required: ['questions'],
            properties: {
              questions: {
                type: 'array',
                minItems: 1,
                maxItems: 20,
                items: {
                  type: 'object',
                  additionalProperties: false,
                  required: ['filePath', 'question', 'options', 'answerIndex', 'rationale', 'hunkSummary'],
                  properties: {
                    filePath: { type: 'string' },
                    question: { type: 'string' },
                    options: {
                      type: 'array',
                      minItems: 4,
                      maxItems: 4,
                      items: { type: 'string' },
                    },
                    answerIndex: { type: 'integer', minimum: 0, maximum: 3 },
                    rationale: { type: 'string' },
                    hunkSummary: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`OpenAI API error: ${response.status}`);
  }

  const data = (await response.json()) as { output_text?: string };
  const output = data.output_text?.trim();
  if (!output) {
    throw new Error('OpenAI response was empty');
  }

  const parsed = JSON.parse(output) as { questions: QuizQuestionInternal[] };
  return parsed.questions;
}

async function getPrivateKey(env: Env): Promise<JoseKey> {
  const privateJwkRaw = env.ATTEST_PRIVATE_JWK;
  if (!privateJwkRaw) {
    throw new Error('ATTEST_PRIVATE_JWK is missing');
  }
  const parsed = JSON.parse(privateJwkRaw);
  if (!isJwk(parsed)) {
    throw new Error('ATTEST_PRIVATE_JWK is missing required fields');
  }
  return importJWK(parsed, ALLOWED_ALG);
}

async function getPublicKey(env: Env): Promise<JoseKey> {
  const publicJwkRaw = env.ATTEST_PUBLIC_JWK;
  if (!publicJwkRaw) {
    throw new Error('ATTEST_PUBLIC_JWK is missing');
  }
  const parsed = JSON.parse(publicJwkRaw);
  if (!isJwk(parsed)) {
    throw new Error('ATTEST_PUBLIC_JWK is missing required fields');
  }
  return importJWK(parsed, ALLOWED_ALG);
}

async function issueAttestationJwt(env: Env, payload: z.infer<typeof attestationSchema>): Promise<{ token: string; exp: number }> {
  if (payload.score !== undefined && payload.score < MIN_SCORE) {
    throw new Error('Score is below required minimum');
  }
  if (payload.duration_ms !== undefined && payload.duration_ms < MIN_DURATION_MS) {
    throw new Error('Duration is below required minimum');
  }

  const issuer = env.ISSUER;
  if (!issuer) {
    throw new Error('ISSUER is missing');
  }

  const key = await getPrivateKey(env);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + THIRTY_DAYS_SEC;

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
    diff_hash: payload.diff_hash ?? null,
    nonce: crypto.randomUUID(),
  };

  const token = await new SignJWT(jwtPayload)
    .setProtectedHeader({ alg: ALLOWED_ALG, kid: KID })
    .setIssuer(issuer)
    .setSubject(payload.sub)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key);

  return { token, exp };
}

function normalizePath(input: string): string {
  return input.replace(/\\/g, '/').replace(/^\.\/+/, '');
}

function isEssentialFile(filePath: string): boolean {
  const file = normalizePath(filePath);
  if (file.startsWith('.bansou/')) return false;
  if (file.startsWith('.github/')) return false;
  if (/\.(md|markdown|json|ya?ml|toml|ini|cfg|lock)$/i.test(file)) return false;
  return true;
}

function requireGateTokenOrSkip(c: any): Response | undefined {
  const expected = c.env.GATE_API_TOKEN;
  if (!expected) {
    return undefined;
  }
  const auth = c.req.header('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token || token !== expected) {
    return jsonError(c, 401, 'unauthorized', 'Invalid gate token');
  }
  return undefined;
}

async function ensureLedgerSchema(db: D1Database): Promise<void> {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS attestations_ledger (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      repo TEXT NOT NULL,
      commit TEXT NOT NULL,
      sub TEXT NOT NULL,
      quiz_id TEXT NOT NULL,
      quiz_version TEXT NOT NULL,
      artifact_path TEXT NOT NULL,
      range_start INTEGER,
      range_end INTEGER,
      score INTEGER NOT NULL,
      questions_hash TEXT,
      answers_hash TEXT,
      diff_hash TEXT,
      created_at TEXT NOT NULL,
      UNIQUE(repo, commit, sub, quiz_id, artifact_path, IFNULL(range_start, -1), IFNULL(range_end, -1))
    );
  `);
}

async function upsertLedgerRecord(
  db: D1Database,
  record: {
    repo: string;
    commit: string;
    sub: string;
    quizId: string;
    quizVersion: string;
    artifactPath: string;
    rangeStart?: number;
    rangeEnd?: number;
    score: number;
    questionsHash?: string;
    answersHash?: string;
    diffHash?: string;
  }
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO attestations_ledger (
        repo, commit, sub, quiz_id, quiz_version, artifact_path, range_start, range_end, score,
        questions_hash, answers_hash, diff_hash, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(repo, commit, sub, quiz_id, artifact_path, IFNULL(range_start, -1), IFNULL(range_end, -1))
      DO UPDATE SET
        score=excluded.score,
        questions_hash=excluded.questions_hash,
        answers_hash=excluded.answers_hash,
        diff_hash=excluded.diff_hash,
        created_at=excluded.created_at`
    )
    .bind(
      record.repo,
      record.commit,
      record.sub,
      record.quizId,
      record.quizVersion,
      normalizePath(record.artifactPath),
      record.rangeStart ?? null,
      record.rangeEnd ?? null,
      record.score,
      record.questionsHash ?? null,
      record.answersHash ?? null,
      record.diffHash ?? null,
      new Date().toISOString()
    )
    .run();
}

app.get('/.well-known/jwks.json', (c) => {
  const raw = c.env.ATTEST_PUBLIC_JWK;
  if (!raw) return jsonError(c, 500, 'server_error', 'ATTEST_PUBLIC_JWK is missing');
  let jwk: JWK;
  try {
    const parsed = JSON.parse(raw);
    if (!isJwk(parsed)) {
      return jsonError(c, 500, 'server_error', 'ATTEST_PUBLIC_JWK is missing required fields');
    }
    jwk = parsed;
  } catch {
    return jsonError(c, 500, 'server_error', 'ATTEST_PUBLIC_JWK is invalid JSON');
  }

  if (!jwk.kid) jwk.kid = KID;
  return c.json({ keys: [jwk] });
});

app.get('/policy', (c) => {
  const raw = c.env.POLICY_JSON;
  if (!raw) return c.json({});
  try {
    return c.json(JSON.parse(raw));
  } catch {
    return c.json({});
  }
});

app.post('/quiz/generate', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return jsonError(c, 400, 'invalid_request', 'Invalid JSON body');
  }

  const parsed = quizGenerateSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed');
  }

  const request = parsed.data;
  const desiredCount = request.desiredQuestionCount ?? Math.min(8, Math.max(3, request.files.length));

  let questions: QuizQuestionInternal[];
  try {
    if (c.env.OPENAI_API_KEY) {
      questions = await generateQuizQuestionsWithOpenAI(
        c.env.OPENAI_API_KEY,
        request.files,
        request.diffsByFile,
        desiredCount
      );
    } else {
      questions = buildTemplateQuestions(request.files, request.diffsByFile, desiredCount);
    }
  } catch {
    questions = buildTemplateQuestions(request.files, request.diffsByFile, desiredCount);
  }

  const boundedQuestions = questions.slice(0, desiredCount);
  const publicQuestions: QuizQuestionPublic[] = boundedQuestions.map((question) => ({
    filePath: question.filePath,
    question: question.question,
    options: question.options,
    rationale: question.rationale,
    hunkSummary: question.hunkSummary,
  }));

  const artifacts = request.artifacts ?? request.files.map((path) => ({ path }));
  const questionsHash = await computeQuestionsHash(boundedQuestions);
  const diffHash = await computeDiffHash(request.diffsByFile);

  const sessionPayload: QuizSessionPayload = {
    repo: request.repo,
    commit: request.commit,
    quiz_id: request.quiz_id,
    quiz_version: request.quiz_version,
    questions: boundedQuestions,
    artifacts,
    questions_hash: questionsHash,
    diff_hash: diffHash,
    nonce: crypto.randomUUID(),
  };

  const issuer = c.env.ISSUER;
  if (!issuer) {
    return jsonError(c, 500, 'server_error', 'ISSUER is missing');
  }

  const key = await getPrivateKey(c.env);
  const now = Math.floor(Date.now() / 1000);
  const exp = now + QUIZ_SESSION_TTL_SEC;
  const quizSessionToken = await new SignJWT(sessionPayload as unknown as JWTPayload)
    .setProtectedHeader({ alg: ALLOWED_ALG, kid: KID })
    .setIssuer(issuer)
    .setSubject(request.sub)
    .setAudience('bansou-quiz-session')
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(key);

  return c.json({
    quiz_id: request.quiz_id,
    quiz_version: request.quiz_version,
    questions_hash: questionsHash,
    diff_hash: diffHash,
    quiz: {
      title: `Quiz for ${request.commit.slice(0, 8)}`,
      questions: publicQuestions,
    },
    quiz_session_token: quizSessionToken,
    exp,
  });
});

app.post('/quiz/submit', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return jsonError(c, 400, 'invalid_request', 'Invalid JSON body');
  }

  const parsed = quizSubmitSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed');
  }

  const request = parsed.data;
  const issuer = c.env.ISSUER;
  if (!issuer) {
    return jsonError(c, 500, 'server_error', 'ISSUER is missing');
  }

  let payload: JWTPayload;
  try {
    const publicKey = await getPublicKey(c.env);
    const verified = await jwtVerify(request.quiz_session_token, publicKey, {
      issuer,
      audience: 'bansou-quiz-session',
    });
    payload = verified.payload;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return jsonError(c, 401, 'invalid_token', message);
  }

  const session = payload as unknown as QuizSessionPayload;
  const subject = payload.sub;
  if (!subject) {
    return jsonError(c, 400, 'invalid_token', 'quiz session token missing sub');
  }

  if (!Array.isArray(session.questions) || session.questions.length === 0) {
    return jsonError(c, 400, 'invalid_token', 'quiz session token missing questions');
  }

  if (request.answers.length !== session.questions.length) {
    return jsonError(c, 400, 'invalid_request', 'answer count mismatch');
  }

  let correct = 0;
  for (let index = 0; index < session.questions.length; index += 1) {
    if (request.answers[index] === session.questions[index].answerIndex) {
      correct += 1;
    }
  }

  const total = session.questions.length;
  const score = total === 0 ? 0 : Math.round((correct / total) * 100);
  const passed = score >= MIN_SCORE;
  const answersHash = await computeAnswersHash(request.answers);

  const attestations: Array<{ artifact: Artifact; attestation_jwt: string; exp: number }> = [];
  let ledgerSaved = false;
  if (passed) {
    if (c.env.ATTEST_DB) {
      await ensureLedgerSchema(c.env.ATTEST_DB);
    }
    for (const artifact of session.artifacts) {
      const result = await issueAttestationJwt(c.env, {
        sub: subject,
        repo: session.repo,
        commit: session.commit,
        artifact,
        quiz_id: session.quiz_id,
        quiz_version: session.quiz_version,
        score,
        duration_ms: request.duration_ms,
        questions_hash: session.questions_hash,
        answers_hash: answersHash,
        diff_hash: session.diff_hash,
      });
      attestations.push({
        artifact,
        attestation_jwt: result.token,
        exp: result.exp,
      });

      if (c.env.ATTEST_DB) {
        await upsertLedgerRecord(c.env.ATTEST_DB, {
          repo: session.repo,
          commit: session.commit,
          sub: subject,
          quizId: session.quiz_id,
          quizVersion: session.quiz_version,
          artifactPath: artifact.path,
          rangeStart: artifact.rangeStart,
          rangeEnd: artifact.rangeEnd,
          score,
          questionsHash: session.questions_hash,
          answersHash,
          diffHash: session.diff_hash,
        });
        ledgerSaved = true;
      }
    }
  }

  return c.json({
    score,
    correct,
    total,
    passed,
    min_score: MIN_SCORE,
    questions_hash: session.questions_hash,
    answers_hash: answersHash,
    diff_hash: session.diff_hash,
    attestations,
    ledger_saved: ledgerSaved,
  });
});

app.post('/gate/evaluate', async (c) => {
  const unauthorized = requireGateTokenOrSkip(c);
  if (unauthorized) {
    return unauthorized;
  }

  if (!c.env.ATTEST_DB) {
    return jsonError(c, 500, 'server_error', 'ATTEST_DB is not configured');
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return jsonError(c, 400, 'invalid_request', 'Invalid JSON body');
  }

  const parsed = gateEvaluateSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed');
  }

  const request = parsed.data;
  const requiredFiles = request.changed_files
    .map((filePath) => normalizePath(filePath))
    .filter((filePath) => isEssentialFile(filePath));

  if (requiredFiles.length === 0) {
    return c.json({
      ok: true,
      required_files: 0,
      covered_files: 0,
      missing_files: [],
      mode: 'no-essential-files',
    });
  }

  await ensureLedgerSchema(c.env.ATTEST_DB);

  const placeholders = requiredFiles.map(() => '?').join(', ');
  const query = `
    SELECT DISTINCT artifact_path
    FROM attestations_ledger
    WHERE repo = ? AND commit = ? AND sub = ? AND quiz_id = ? AND artifact_path IN (${placeholders})
  `;
  const bindings: unknown[] = [
    request.repo,
    request.commit,
    request.sub,
    request.required_quiz_id,
    ...requiredFiles,
  ];

  const rowsResult = await c.env.ATTEST_DB.prepare(query).bind(...bindings).all<{
    artifact_path: string;
  }>();
  const covered = new Set(
    (rowsResult.results || [])
      .map((row) => normalizePath(row.artifact_path))
      .filter(Boolean)
  );
  const missing = requiredFiles.filter((filePath) => !covered.has(filePath));

  return c.json({
    ok: missing.length === 0,
    required_files: requiredFiles.length,
    covered_files: covered.size,
    missing_files: missing,
    mode: 'commit-exact',
  });
});

app.post('/attestations/issue', async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return jsonError(c, 400, 'invalid_request', 'Invalid JSON body');
  }

  const parsed = attestationSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError(c, 400, 'invalid_request', 'Request validation failed');
  }

  try {
    const result = await issueAttestationJwt(c.env, parsed.data);
    return c.json({
      attestation_jwt: result.token,
      commit: parsed.data.commit,
      quiz_id: parsed.data.quiz_id,
      exp: result.exp,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes('Score is below required minimum')) {
      return jsonError(c, 403, 'forbidden', message);
    }
    if (message.includes('Duration is below required minimum')) {
      return jsonError(c, 403, 'forbidden', message);
    }
    return jsonError(c, 500, 'server_error', message);
  }
});

export default app;
