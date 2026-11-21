import type { APIGatewayProxyHandlerV2 } from 'aws-lambda';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { SQSClient, SendMessageCommand } from '@aws-sdk/client-sqs';
import { SageMakerRuntimeClient, InvokeEndpointCommand } from '@aws-sdk/client-sagemaker-runtime';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3Client = new S3Client({});
const sqsClient = new SQSClient({});

type Decision = 'allow' | 'throttle' | 'flag';

const FREQ_THRESHOLD = 25;
const REPEAT_CONSEC = 4;
const FAST_MS = 200;
/** Rolling window of route keys for sequence / cross-request analysis */
const ROUTE_SEQUENCE_MAX = 16;

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env ${name}`);
  return v;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function minuteKeyFromEpoch(ms: number): string {
  return new Date(ms).toISOString().slice(0, 16);
}

interface VelocityRow {
  lastRequestEpochMs?: number;
  minuteKey?: string;
  requestsInMinute?: number;
  lastRouteKey?: string;
  consecutiveSameRoute?: number;
  lastAuthorityChangeEpochMs?: number;
  helloHits?: number;
  /** Ordered recent routeKey values (cross-request state) */
  routeSequence?: string[];
}

interface BudgetRow {
  spend?: number;
}

interface AuthorityProfileRow {
  authorityLevel?: number;
}

/** Long-horizon principal profile (cross-session) */
interface CrossSessionRow {
  ewmaRisk?: number;
  totalRequests?: number;
  distinctDays?: number;
  lastDay?: string;
  recentSourceIps?: string[];
}

/** Adaptive learning: biases (feedback + implicit loops) + behavioral EWMA for self-adjusting thresholds */
interface AdaptiveTuningRow {
  leniencyBias?: number;
  strictnessBias?: number;
  ewmaRequestsPerMinute?: number;
  ewmaInterRequestMs?: number;
  allowDecisionEma?: number;
  feedbackFpCount?: number;
  feedbackTpCount?: number;
}

/** Per-request (point) anomaly signals */
interface PointSignals {
  high_frequency: boolean;
  repeated_pattern: boolean;
  fast_timing: boolean;
}

/** Cross-request / sequence-derived signals */
interface SequenceSignals {
  seq_high_churn: boolean;
  seq_two_cycle: boolean;
  seq_distinct_burst: boolean;
  seq_entropy_high: boolean;
  seq_repeated_bigram: boolean;
}

interface CrossIntelligenceSignals {
  cross_session_spike: boolean;
  cross_ip_change: boolean;
  ml_anomaly: boolean;
}

type Signals = PointSignals & SequenceSignals & CrossIntelligenceSignals;

function normalizeRouteSequence(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === 'string').slice(-ROUTE_SEQUENCE_MAX);
}

function routeEntropy(routes: string[]): number {
  if (routes.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const r of routes) counts.set(r, (counts.get(r) ?? 0) + 1);
  const n = routes.length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function maxBigramRepeatCount(routes: string[]): number {
  if (routes.length < 2) return 0;
  const bigrams = new Map<string, number>();
  for (let i = 0; i < routes.length - 1; i++) {
    const k = `${routes[i]}\n${routes[i + 1]}`;
    bigrams.set(k, (bigrams.get(k) ?? 0) + 1);
  }
  let m = 0;
  for (const c of bigrams.values()) m = Math.max(m, c);
  return m;
}

/**
 * Cross-request pattern detection on the rolling sequence (after appending current route).
 */
function detectCrossRequestPatterns(seq: string[]): SequenceSignals {
  const n = seq.length;
  const tail = (k: number) => seq.slice(-Math.min(k, n));

  const uniq = new Set(seq).size;
  const seq_high_churn = n >= 8 && (uniq >= 7 || uniq / n >= 0.72);

  let seq_two_cycle = false;
  if (n >= 6) {
    const t = tail(6);
    if (t[0] !== t[1]) {
      seq_two_cycle = t.every((r, i) => i < 2 || r === t[i - 2]);
    }
  }

  const last5 = tail(5);
  const seq_distinct_burst = last5.length >= 5 && new Set(last5).size === 5;

  const entWindow = tail(Math.min(10, n));
  const seq_entropy_high = entWindow.length >= 6 && routeEntropy(entWindow) > 2.15;

  const biWindow = tail(Math.min(12, n));
  const seq_repeated_bigram = biWindow.length >= 8 && maxBigramRepeatCount(biWindow) >= 4;

  return {
    seq_high_churn,
    seq_two_cycle,
    seq_distinct_burst,
    seq_entropy_high,
    seq_repeated_bigram,
  };
}

function computePointSignals(
  prev: VelocityRow,
  routeKey: string,
  nowMs: number,
  thresholds: { freq: number; fastMs: number; repeat: number },
): { point: PointSignals; interRequestMs: number | null; nextVelocity: Record<string, unknown> } {
  const lastMs = prev.lastRequestEpochMs;
  const interRequestMs = lastMs != null ? nowMs - lastMs : null;

  let minuteKey = prev.minuteKey;
  let requestsInMinute = prev.requestsInMinute ?? 0;
  const mk = minuteKeyFromEpoch(nowMs);
  if (mk !== minuteKey) {
    minuteKey = mk;
    requestsInMinute = 1;
  } else {
    requestsInMinute += 1;
  }

  const lastRoute = prev.lastRouteKey ?? '';
  let consecutiveSameRoute = 1;
  if (lastRoute === routeKey) {
    consecutiveSameRoute = (prev.consecutiveSameRoute ?? 0) + 1;
  }

  const high_frequency = requestsInMinute > thresholds.freq;
  const repeated_pattern = consecutiveSameRoute >= thresholds.repeat;
  const fast_timing =
    interRequestMs != null && interRequestMs > 0 && interRequestMs < thresholds.fastMs;

  const nextVelocity: Record<string, unknown> = {
    lastRequestEpochMs: nowMs,
    minuteKey,
    requestsInMinute,
    lastRouteKey: routeKey,
    consecutiveSameRoute,
  };

  return {
    point: { high_frequency, repeated_pattern, fast_timing },
    interRequestMs,
    nextVelocity,
  };
}

function scorePointRisk(p: PointSignals): number {
  let s = 0;
  if (p.high_frequency) s += 0.4;
  if (p.repeated_pattern) s += 0.3;
  if (p.fast_timing) s += 0.3;
  return Math.min(1, s);
}

/** Sequence layer capped so point + sequence can combine without saturating immediately */
function scoreSequenceRisk(seq: SequenceSignals): number {
  let s = 0;
  if (seq.seq_high_churn) s += 0.16;
  if (seq.seq_two_cycle) s += 0.14;
  if (seq.seq_distinct_burst) s += 0.12;
  if (seq.seq_entropy_high) s += 0.1;
  if (seq.seq_repeated_bigram) s += 0.1;
  return Math.min(0.48, s);
}

function combineRisk(pointRisk: number, sequenceRisk: number): number {
  return Math.min(1, Math.round((pointRisk + sequenceRisk) * 100) / 100);
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function effectiveThresholds(tuning: AdaptiveTuningRow): { freq: number; fastMs: number; repeat: number } {
  const len = clamp(tuning.leniencyBias ?? 0, 0, 0.22);
  const strict = clamp(tuning.strictnessBias ?? 0, 0, 0.22);
  const m = clamp(1 + len - strict, 0.78, 1.28);
  const rpm = tuning.ewmaRequestsPerMinute ?? 0;
  const rpmScale =
    rpm > 0.5 ? clamp(1 + (rpm / FREQ_THRESHOLD - 1) * 0.18, 0.88, 1.22) : 1;
  return {
    freq: Math.round(clamp(FREQ_THRESHOLD * m * rpmScale, 10, 90)),
    fastMs: Math.round(
      clamp(
        FAST_MS * (1.35 - (m - 1) * 0.5) *
          (tuning.ewmaInterRequestMs != null && tuning.ewmaInterRequestMs > 200 ? 1.08 : 1),
        85,
        380,
      ),
    ),
    repeat: Math.round(clamp(REPEAT_CONSEC * m, 3, 12)),
  };
}

function evolveAdaptiveTuning(
  prev: AdaptiveTuningRow,
  args: {
    requestsInMinute: number;
    interRequestMs: number | null;
    decision: Decision;
    riskScore: number;
  },
): AdaptiveTuningRow {
  const a = 0.07;
  const ewmaRpm = (1 - a) * (prev.ewmaRequestsPerMinute ?? 0) + a * args.requestsInMinute;
  const prevIrt = prev.ewmaInterRequestMs ?? 280;
  const ewmaIrt =
    args.interRequestMs != null
      ? (1 - a) * prevIrt + a * args.interRequestMs
      : prevIrt;

  const allowE =
    (1 - 0.06) * (prev.allowDecisionEma ?? 0.5) + 0.06 * (args.decision === 'allow' ? 1 : 0);

  let len = (prev.leniencyBias ?? 0) * 0.998;
  let strict = (prev.strictnessBias ?? 0) * 0.998;

  if (allowE > 0.86 && args.riskScore < 0.18) {
    len = Math.min(0.22, len + 0.0025);
  }
  if (args.decision === 'flag' || (args.decision === 'throttle' && args.riskScore > 0.55)) {
    strict = Math.min(0.22, strict + 0.0018);
  }

  return {
    ...prev,
    leniencyBias: clamp(len, 0, 0.22),
    strictnessBias: clamp(strict, 0, 0.22),
    ewmaRequestsPerMinute: ewmaRpm,
    ewmaInterRequestMs: ewmaIrt,
    allowDecisionEma: allowE,
    feedbackFpCount: prev.feedbackFpCount ?? 0,
    feedbackTpCount: prev.feedbackTpCount ?? 0,
  };
}

function applyFeedbackToTuning(prev: AdaptiveTuningRow, verdict: string): AdaptiveTuningRow {
  let len = prev.leniencyBias ?? 0;
  let strict = prev.strictnessBias ?? 0;
  let fp = prev.feedbackFpCount ?? 0;
  let tp = prev.feedbackTpCount ?? 0;
  if (verdict === 'false_alarm' || verdict === 'benign_override') {
    len = Math.min(0.22, len + 0.055);
    strict = Math.max(0, strict - 0.02);
    fp += 1;
  } else if (verdict === 'confirmed_threat') {
    strict = Math.min(0.22, strict + 0.055);
    len = Math.max(0, len - 0.02);
    tp += 1;
  }
  return {
    ...prev,
    leniencyBias: len,
    strictnessBias: strict,
    feedbackFpCount: fp,
    feedbackTpCount: tp,
  };
}

function normalizeSourceIps(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === 'string').slice(0, 8);
}

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

async function invokeMlAnomaly(endpointName: string | undefined, features: number[]): Promise<number> {
  if (!endpointName) return 0;
  try {
    const client = new SageMakerRuntimeClient({});
    const out = await client.send(
      new InvokeEndpointCommand({
        EndpointName: endpointName,
        Body: Buffer.from(JSON.stringify({ features })),
        ContentType: 'application/json',
        Accept: 'application/json',
      }),
    );
    const raw = new TextDecoder().decode(out.Body);
    const parsed = JSON.parse(raw) as {
      score?: number;
      anomaly_score?: number;
      predictions?: number[];
    };
    if (typeof parsed.score === 'number') return clamp01(parsed.score);
    if (typeof parsed.anomaly_score === 'number') return clamp01(parsed.anomaly_score);
    if (Array.isArray(parsed.predictions) && typeof parsed.predictions[0] === 'number') {
      return clamp01(parsed.predictions[0]);
    }
    const n = Number(raw);
    return Number.isFinite(n) ? clamp01(n) : 0;
  } catch {
    return 0;
  }
}

function buildMlFeatures(args: {
  riskPoint: number;
  riskSequence: number;
  riskBase: number;
  requestsInMinute: number;
  consecutiveSameRoute: number;
  interRequestMs: number | null;
  routeSequence: string[];
  sequencePatterns: SequenceSignals;
  ewmaRisk: number;
  totalRequests: number;
  crossSpike: boolean;
  crossIp: boolean;
  effFreq: number;
  effFastMs: number;
  effRepeat: number;
  leniencyBias: number;
  strictnessBias: number;
  allowDecisionEma: number;
}): number[] {
  const seq = args.routeSequence;
  const uniq = new Set(seq).size;
  const ent = seq.length >= 4 ? routeEntropy(seq.slice(-10)) : 0;
  return [
    args.riskPoint,
    args.riskSequence,
    args.riskBase,
    Math.min(1, args.requestsInMinute / 40),
    Math.min(1, args.consecutiveSameRoute / 10),
    args.interRequestMs != null && args.interRequestMs > 0
      ? Math.min(1, 800 / args.interRequestMs)
      : 0,
    seq.length ? uniq / seq.length : 0,
    Math.min(1, ent / 4),
    args.sequencePatterns.seq_high_churn ? 1 : 0,
    args.sequencePatterns.seq_two_cycle ? 1 : 0,
    args.sequencePatterns.seq_entropy_high ? 1 : 0,
    args.ewmaRisk,
    Math.min(1, args.totalRequests / 800),
    args.crossSpike ? 1 : 0,
    args.crossIp ? 1 : 0,
    Math.min(1, args.effFreq / 100),
    Math.min(1, args.effFastMs / 400),
    Math.min(1, args.effRepeat / 14),
    args.leniencyBias,
    args.strictnessBias,
    args.allowDecisionEma,
  ];
}

function decideFromRiskAdaptive(
  risk: number,
  tuning: AdaptiveTuningRow,
): { decision: Decision; throttleMs: number; threshold_throttle: number; threshold_flag: number } {
  const adjust = (tuning.strictnessBias ?? 0) - (tuning.leniencyBias ?? 0);
  const thresholdThrottle = clamp(0.4 - adjust * 0.12, 0.26, 0.52);
  const thresholdFlag = clamp(0.7 - adjust * 0.14, 0.52, 0.85);
  if (risk >= thresholdFlag) return { decision: 'flag', throttleMs: 280, threshold_throttle: thresholdThrottle, threshold_flag: thresholdFlag };
  if (risk >= thresholdThrottle)
    return { decision: 'throttle', throttleMs: 650, threshold_throttle: thresholdThrottle, threshold_flag: thresholdFlag };
  return { decision: 'allow', throttleMs: 0, threshold_throttle: thresholdThrottle, threshold_flag: thresholdFlag };
}

function applyAbuseBudget(
  remaining: number,
  decision: Decision,
  throttleMs: number,
): { decision: Decision; throttleMs: number } {
  if (remaining >= 30) return { decision, throttleMs };
  if (decision === 'allow') return { decision: 'throttle', throttleMs: Math.max(throttleMs, 420) };
  if (decision === 'throttle') return { decision: 'flag', throttleMs: Math.max(throttleMs, 720) };
  return { decision, throttleMs };
}

function nextAuthorityLevel(prevLevel: number, risk: number): number {
  if (risk >= 0.75) return Math.min(3, prevLevel + 1);
  if (risk < 0.15) return Math.max(0, prevLevel - 1);
  return prevLevel;
}

export const handler: APIGatewayProxyHandlerV2 = async (event) => {
  const method = event.requestContext.http.method;
  if (method === 'POST' && event.rawPath === '/feedback') {
    return handleFeedback(event);
  }
  return handleHello(event);
};

async function handleFeedback(
  event: Parameters<APIGatewayProxyHandlerV2>[0],
): Promise<ReturnType<APIGatewayProxyHandlerV2>> {
  const authorityState = requireEnv('AUTHORITY_STATE_TABLE');
  const sub =
    (event.requestContext as { authorizer?: { jwt?: { claims?: { sub?: string } } } }).authorizer?.jwt
      ?.claims?.sub;
  if (!sub) {
    return {
      statusCode: 401,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'unauthorized' }),
    };
  }

  let body: { verdict?: string; requestId?: string };
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return {
      statusCode: 400,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'invalid_json' }),
    };
  }

  const verdict = body.verdict;
  if (
    verdict !== 'false_alarm' &&
    verdict !== 'confirmed_threat' &&
    verdict !== 'benign_override'
  ) {
    return {
      statusCode: 400,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        error: 'invalid_verdict',
        allowed: ['false_alarm', 'confirmed_threat', 'benign_override'],
      }),
    };
  }

  const pkSub = `SUB#${sub}`;
  const tuneRes = await ddb.send(
    new GetCommand({
      TableName: authorityState,
      Key: { pk: pkSub, sk: 'ADAPTIVE_TUNING' },
    }),
  );
  const prev = (tuneRes.Item ?? {}) as AdaptiveTuningRow;
  const next = applyFeedbackToTuning(prev, verdict);

  const item: Record<string, unknown> = {
    pk: pkSub,
    sk: 'ADAPTIVE_TUNING',
    ...next,
    updatedAt: new Date().toISOString(),
    lastVerdict: verdict,
  };
  if (body.requestId) item.lastFeedbackRequestId = body.requestId;

  await ddb.send(
    new PutCommand({
      TableName: authorityState,
      Item: item,
    }),
  );

  return {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      ok: true,
      verdict,
      adaptive: {
        ...next,
        effective_thresholds: effectiveThresholds(next),
      },
    }),
  };
}

async function handleHello(
  event: Parameters<APIGatewayProxyHandlerV2>[0],
): Promise<ReturnType<APIGatewayProxyHandlerV2>> {
  const requestId = event.requestContext.requestId;
  const ts = new Date().toISOString();
  const nowMs = Date.now();
  const sub =
    (event.requestContext as { authorizer?: { jwt?: { claims?: { sub?: string } } } }).authorizer?.jwt
      ?.claims?.sub ?? 'unknown';
  const routeKey = event.routeKey ?? `${event.requestContext.http.method} ${event.rawPath}`;

  const authorityState = requireEnv('AUTHORITY_STATE_TABLE');
  const abuseBudgetTable = requireEnv('ABUSE_BUDGET_TABLE');
  const authorityVelocityTable = requireEnv('AUTHORITY_VELOCITY_TABLE');
  const requestLogIndex = requireEnv('REQUEST_LOG_INDEX_TABLE');
  const auditBucket = requireEnv('AUDIT_BUCKET_NAME');

  const dayWindow = ts.slice(0, 10);
  const pkSub = `SUB#${sub}`;

  const [velRes, budgetRes, profileRes, crossRes, tuneRes] = await Promise.all([
    ddb.send(
      new GetCommand({
        TableName: authorityVelocityTable,
        Key: { principalKey: sub },
      }),
    ),
    ddb.send(
      new GetCommand({
        TableName: abuseBudgetTable,
        Key: { principalKey: sub, windowId: dayWindow },
      }),
    ),
    ddb.send(
      new GetCommand({
        TableName: authorityState,
        Key: { pk: pkSub, sk: 'AUTHORITY_PROFILE' },
      }),
    ),
    ddb.send(
      new GetCommand({
        TableName: authorityState,
        Key: { pk: pkSub, sk: 'CROSS_SESSION' },
      }),
    ),
    ddb.send(
      new GetCommand({
        TableName: authorityState,
        Key: { pk: pkSub, sk: 'ADAPTIVE_TUNING' },
      }),
    ),
  ]);

  const prevVel = (velRes.Item ?? {}) as VelocityRow;
  const cross = (crossRes.Item ?? {}) as CrossSessionRow;
  const tuningRow = (tuneRes.Item ?? {}) as AdaptiveTuningRow;
  const thresholds = effectiveThresholds(tuningRow);
  const sourceIp = event.requestContext.http?.sourceIp ?? 'unknown';

  const { point, interRequestMs, nextVelocity } = computePointSignals(
    prevVel,
    routeKey,
    nowMs,
    thresholds,
  );
  const requestsInMinute = (nextVelocity.requestsInMinute as number) ?? 0;
  const consecutiveSameRoute = (nextVelocity.consecutiveSameRoute as number) ?? 0;

  const prevSeq = normalizeRouteSequence(prevVel.routeSequence);
  const routeSequence = [...prevSeq, routeKey].slice(-ROUTE_SEQUENCE_MAX);
  const sequencePatterns = detectCrossRequestPatterns(routeSequence);

  const riskPoint = scorePointRisk(point);
  const riskSequence = scoreSequenceRisk(sequencePatterns);
  const riskBase = combineRisk(riskPoint, riskSequence);

  const recentIps = normalizeSourceIps(cross.recentSourceIps);
  const cross_session_spike =
    (cross.totalRequests ?? 0) > 6 && riskBase > (cross.ewmaRisk ?? 0) + 0.32;
  const cross_ip_change = !recentIps.includes(sourceIp) && recentIps.length >= 4;

  let riskCross = Math.min(
    1,
    Math.round((riskBase + (cross_session_spike ? 0.12 : 0) + (cross_ip_change ? 0.06 : 0)) * 100) /
      100,
  );

  const crossSpikeForMl = cross_session_spike;
  const crossIpForMl = cross_ip_change;

  const mlEndpoint = process.env.SAGEMAKER_ANOMALY_ENDPOINT;
  const mlFeatures = buildMlFeatures({
    riskPoint,
    riskSequence,
    riskBase,
    requestsInMinute,
    consecutiveSameRoute,
    interRequestMs,
    routeSequence,
    sequencePatterns,
    ewmaRisk: cross.ewmaRisk ?? 0,
    totalRequests: cross.totalRequests ?? 0,
    crossSpike: crossSpikeForMl,
    crossIp: crossIpForMl,
    effFreq: thresholds.freq,
    effFastMs: thresholds.fastMs,
    effRepeat: thresholds.repeat,
    leniencyBias: tuningRow.leniencyBias ?? 0,
    strictnessBias: tuningRow.strictnessBias ?? 0,
    allowDecisionEma: tuningRow.allowDecisionEma ?? 0.5,
  });
  const mlRaw = await invokeMlAnomaly(mlEndpoint, mlFeatures);
  const ml_anomaly = mlRaw >= 0.45;
  const riskScore =
    mlEndpoint && mlRaw > 0
      ? Math.min(1, Math.round((riskCross * 0.72 + mlRaw * 0.28) * 100) / 100)
      : riskCross;

  const signals: Signals = {
    ...point,
    ...sequencePatterns,
    cross_session_spike,
    cross_ip_change,
    ml_anomaly,
  };

  const budget = (budgetRes.Item ?? {}) as BudgetRow;
  const spend = budget.spend ?? 0;
  const budgetMax = 100;
  const remaining = Math.max(0, budgetMax - spend);

  let { decision, throttleMs, threshold_throttle, threshold_flag } = decideFromRiskAdaptive(
    riskScore,
    tuningRow,
  );
  ({ decision, throttleMs } = applyAbuseBudget(remaining, decision, throttleMs));

  const nextTuning = evolveAdaptiveTuning(tuningRow, {
    requestsInMinute,
    interRequestMs,
    decision,
    riskScore,
  });

  const prevAuthorityLevel = (profileRes.Item as AuthorityProfileRow | undefined)?.authorityLevel ?? 0;
  const authorityLevel = nextAuthorityLevel(prevAuthorityLevel, riskScore);
  const authorityDelta = authorityLevel - prevAuthorityLevel;

  const lastChange = prevVel.lastAuthorityChangeEpochMs ?? 0;
  const minutesSinceChange = lastChange > 0 ? (nowMs - lastChange) / 60_000 : 0;
  const authorityVelocityPerMinute =
    authorityDelta !== 0 && minutesSinceChange > 0
      ? Math.round((authorityDelta / minutesSinceChange) * 1000) / 1000
      : authorityDelta !== 0
        ? authorityDelta
        : 0;

  const lastAuthorityChangeEpochMs =
    authorityDelta !== 0 ? nowMs : prevVel.lastAuthorityChangeEpochMs ?? nowMs;

  const nextEwmaRisk = (cross.ewmaRisk ?? 0) * 0.88 + riskScore * 0.12;
  const nextTotalRequests = (cross.totalRequests ?? 0) + 1;
  const nextDistinctDays =
    cross.lastDay === dayWindow ? (cross.distinctDays ?? 0) : (cross.distinctDays ?? 0) + 1;
  const nextRecentIps = [...new Set([sourceIp, ...recentIps])].slice(0, 6);

  await sleep(throttleMs);

  const newSpend = spend + Math.round(riskScore * 20);

  const velocityItem = {
    principalKey: sub,
    lastSeen: ts,
    lastRequestId: requestId,
    helloHits: (prevVel.helloHits ?? 0) + 1,
    ...nextVelocity,
    routeSequence,
    authorityLevel,
    previousAuthorityLevel: prevAuthorityLevel,
    lastAuthorityDelta: authorityDelta,
    lastAuthorityChangeEpochMs,
    authorityVelocityPerMinute,
  };

  const auditPayload = {
    requestId,
    ts,
    sub,
    routeKey,
    source_ip: sourceIp,
    risk_score: riskScore,
    risk_base: riskBase,
    risk_cross: riskCross,
    risk_point: riskPoint,
    risk_sequence: riskSequence,
    ml_raw_score: mlRaw,
    ml_endpoint_configured: Boolean(mlEndpoint),
    route_sequence_len: routeSequence.length,
    route_sequence_tail: routeSequence.slice(-6),
    decision,
    authority_level: authorityLevel,
    authority_delta: authorityDelta,
    authority_velocity_per_minute: authorityVelocityPerMinute,
    throttle_ms_applied: throttleMs,
    signals,
    inter_request_ms: interRequestMs,
    abuse_budget_remaining_before: remaining,
    abuse_spend_after: newSpend,
    cross_session: {
      ewma_risk_before: cross.ewmaRisk ?? 0,
      ewma_risk_after: nextEwmaRisk,
      total_requests_after: nextTotalRequests,
      distinct_days: nextDistinctDays,
      recent_source_ips: nextRecentIps,
    },
    adaptive: {
      effective_thresholds: thresholds,
      decision_thresholds: { throttle: threshold_throttle, flag: threshold_flag },
      next_tuning: nextTuning,
      feedback_fp: nextTuning.feedbackFpCount ?? 0,
      feedback_tp: nextTuning.feedbackTpCount ?? 0,
    },
  };

  const persist: Promise<unknown>[] = [
    ddb.send(
      new PutCommand({
        TableName: requestLogIndex,
        Item: {
          requestId,
          ts,
          sub,
          routeKey,
          source_ip: sourceIp,
          risk_score: riskScore,
          risk_base: riskBase,
          risk_cross: riskCross,
          risk_point: riskPoint,
          risk_sequence: riskSequence,
          ml_raw_score: mlRaw,
          decision,
          authority_level: authorityLevel,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityState,
        Item: {
          pk: pkSub,
          sk: 'LATEST_RISK',
          risk_score: riskScore,
          risk_point: riskPoint,
          risk_sequence: riskSequence,
          decision,
          authority_level: authorityLevel,
          requestId,
          ts,
          signals,
          route_sequence_tail: routeSequence.slice(-8),
          risk_base: riskBase,
          risk_cross: riskCross,
          ml_raw_score: mlRaw,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityState,
        Item: {
          pk: pkSub,
          sk: 'CROSS_SESSION',
          ewmaRisk: nextEwmaRisk,
          totalRequests: nextTotalRequests,
          distinctDays: nextDistinctDays,
          lastDay: dayWindow,
          recentSourceIps: nextRecentIps,
          updatedAt: ts,
          lastRequestId: requestId,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityState,
        Item: {
          pk: pkSub,
          sk: 'ADAPTIVE_TUNING',
          ...nextTuning,
          updatedAt: ts,
          lastRequestId: requestId,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityState,
        Item: {
          pk: pkSub,
          sk: 'AUTHORITY_PROFILE',
          authorityLevel,
          lastDecision: decision,
          updatedAt: ts,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityState,
        Item: {
          pk: pkSub,
          sk: 'HELLO_LAST',
          lastRequestId: requestId,
          lastTs: ts,
          risk_score: riskScore,
          decision,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: abuseBudgetTable,
        Item: {
          principalKey: sub,
          windowId: dayWindow,
          spend: newSpend,
          lastRouteKey: routeKey,
          updatedAt: ts,
          lastDecision: decision,
        },
      }),
    ),
    ddb.send(
      new PutCommand({
        TableName: authorityVelocityTable,
        Item: velocityItem,
      }),
    ),
    s3Client.send(
      new PutObjectCommand({
        Bucket: auditBucket,
        Key: `api-decisions/${dayWindow}/${requestId}.json`,
        Body: JSON.stringify(auditPayload),
        ContentType: 'application/json',
      }),
    ),
  ];

  const streamQueueUrl = process.env.SECURITY_EVENTS_QUEUE_URL;
  if (streamQueueUrl) {
    persist.push(
      sqsClient.send(
        new SendMessageCommand({
          QueueUrl: streamQueueUrl,
          MessageBody: JSON.stringify(auditPayload),
        }),
      ),
    );
  }

  await Promise.all(persist);

  console.log(
    JSON.stringify({
      MLAITDS_AUDIT: true,
      ...auditPayload,
    }),
  );

  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-mlaitds-risk-score': String(riskScore),
    'x-mlaitds-decision': decision,
    'x-mlaitds-authority-level': String(authorityLevel),
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify({
      ok: true,
      requestId,
      sub,
      risk_score: riskScore,
      risk_base: riskBase,
      risk_cross: riskCross,
      risk_point: riskPoint,
      risk_sequence: riskSequence,
      ml_raw_score: mlRaw,
      decision,
      authority_level: authorityLevel,
      adaptive: auditPayload.adaptive,
    }),
  };
}
