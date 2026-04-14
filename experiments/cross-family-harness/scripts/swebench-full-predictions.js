// swebench-full-predictions.js — generate patches for 30 SWE-bench-lite tasks
// across 6 configs (3 solo + 3 cross-family). No Docker, no evaluation.
// Output: results/swebench-full-predictions.jsonl for later x86 eval.
//
// Usage: node scripts/swebench-full-predictions.js
// Can be killed and restarted; checkpoints via existing JSONL rows.

import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HARNESS = join(__dirname, '..');
const TASKS_PATH = join(HARNESS, 'data', 'swebench-lite-30tasks.json');
const RESULTS = join(HARNESS, 'results', 'swebench-full-predictions.jsonl');

const envPath = join(HARNESS, '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) process.env[m[1]] = m[2];
  }
}

const PRICING = {
  'claude-opus-4-6':         { input: 15.0, output: 75.0 },
  'gpt-5.4':                 { input: 5.0,  output: 20.0 },
  'gemini-3.1-pro-preview':  { input: 2.5,  output: 10.0 },
};

const MODELS = {
  claude: { slug: 'claude-opus-4-6',         provider: 'anthropic' },
  gpt:    { slug: 'gpt-5.4',                 provider: 'openai' },
  gemini: { slug: 'gemini-3.1-pro-preview',  provider: 'google' },
};

// Config definitions. executor_key and reviewer_key index into MODELS.
// Workers are bucketed by executor_key to spread load across providers.
const CONFIGS = [
  { name: 'solo-claude',            executor: 'claude', reviewer: null     },
  { name: 'solo-gpt',               executor: 'gpt',    reviewer: null     },
  { name: 'solo-gemini',            executor: 'gemini', reviewer: null     },
  { name: 'claude-reviews-gpt',     executor: 'gpt',    reviewer: 'claude' },
  { name: 'gpt-reviews-gemini',     executor: 'gemini', reviewer: 'gpt'    },
  { name: 'gemini-reviews-claude',  executor: 'claude', reviewer: 'gemini' },
];

const EXEC_SYSTEM = "You are a software engineer. Output ONLY a unified diff patch. Start with 'diff --git'. No prose, no markdown fences, no explanation. If the fix spans multiple files, include all hunks in one diff.";
const REVIEWER_SYSTEM = "You are a code reviewer. Examine the patch for correctness against the issue. Output ONLY valid JSON with keys: flag (bool), reason (string), proposed_fix (string or null), confidence (number 0-1). flag=true if the patch is wrong or incomplete.";

const EXEC_MAX_TOKENS = 2048;
const REVIEWER_MAX_TOKENS = 1024;

const HARD_CAP = 80.0;
const WARN_CAP = 50.0;

// Shared state.
let totalCost = 0;
let warnLogged = false;
const startTime = Date.now();

function parsesAsDiff(text) {
  if (!text) return false;
  const t = text.trim();
  const startsOk = /^(diff --git|---\s)/m.test(t.slice(0, 200));
  const hasPlus = /^\+\+\+\s/m.test(t);
  const hasHunk = /^@@\s/m.test(t);
  return startsOk && hasPlus && hasHunk;
}

function extractDiff(text) {
  if (!text) return '';
  let t = text.trim();
  const fence = t.match(/```(?:diff|patch)?\s*\n([\s\S]*?)```/);
  if (fence) t = fence[1].trim();
  return t;
}

function parseReviewerJson(text) {
  if (!text) return null;
  let s = text.trim();
  const fence = s.match(/```(?:json)?\s*\n([\s\S]*?)```/);
  if (fence) s = fence[1].trim();
  const braceStart = s.indexOf('{');
  const braceEnd = s.lastIndexOf('}');
  if (braceStart < 0 || braceEnd < 0) return null;
  try {
    return JSON.parse(s.slice(braceStart, braceEnd + 1));
  } catch {
    return null;
  }
}

function costOf(slug, inTok, outTok) {
  const p = PRICING[slug];
  return (inTok * p.input + outTok * p.output) / 1_000_000;
}

async function callAnthropic(slug, system, user, maxTokens) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();
  const start = Date.now();
  const r = await client.messages.create({
    model: slug, max_tokens: maxTokens, system,
    messages: [{ role: 'user', content: user }],
  });
  return {
    text: r.content.map(c => c.text || '').join(''),
    input_tokens: r.usage.input_tokens,
    output_tokens: r.usage.output_tokens,
    latency_ms: Date.now() - start,
  };
}

async function callOpenAI(slug, system, user, maxTokens) {
  const { default: OpenAI } = await import('openai');
  const client = new OpenAI();
  const start = Date.now();
  let r;
  try {
    r = await client.chat.completions.create({
      model: slug, max_completion_tokens: maxTokens,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
    });
  } catch (e) {
    r = await client.chat.completions.create({
      model: slug, max_tokens: maxTokens,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
    });
  }
  return {
    text: r.choices[0].message.content || '',
    input_tokens: r.usage.prompt_tokens,
    output_tokens: r.usage.completion_tokens,
    latency_ms: Date.now() - start,
  };
}

async function callGoogle(slug, system, user, _maxTokens) {
  const { GoogleGenerativeAI } = await import('@google/generative-ai');
  const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);
  const model = genAI.getGenerativeModel({ model: slug, systemInstruction: system });
  const start = Date.now();
  const result = await model.generateContent(user);
  const response = result.response;
  const usage = response.usageMetadata || {};
  return {
    text: response.text(),
    input_tokens: usage.promptTokenCount || 0,
    output_tokens: usage.candidatesTokenCount || 0,
    latency_ms: Date.now() - start,
  };
}

async function callModel(modelKey, system, user, maxTokens) {
  const m = MODELS[modelKey];
  if (m.provider === 'anthropic') return callAnthropic(m.slug, system, user, maxTokens);
  if (m.provider === 'openai')    return callOpenAI(m.slug, system, user, maxTokens);
  if (m.provider === 'google')    return callGoogle(m.slug, system, user, maxTokens);
  throw new Error('unknown provider');
}

function buildExecUserPrompt(task, reviewerFeedback) {
  let s = `Repo: ${task.repo}\nBase commit: ${task.base_commit}\n\nIssue:\n${task.problem_statement}\n`;
  if (task.hints_text && task.hints_text.length) s += `\nHints:\n${task.hints_text}\n`;
  if (reviewerFeedback) {
    s += `\nA reviewer flagged a previous attempt with this reason:\n${reviewerFeedback}\n\nProduce a revised unified diff that addresses the reviewer's concern.`;
  } else {
    s += '\nProduce the unified diff:';
  }
  return s;
}

function buildReviewerUserPrompt(task, patch) {
  return `Repo: ${task.repo}\nBase commit: ${task.base_commit}\n\nIssue:\n${task.problem_statement}\n\nCandidate patch:\n${patch}\n\nReturn JSON verdict.`;
}

function maybeLogCostMilestones() {
  if (totalCost > HARD_CAP) {
    console.error(`\nHARD CAP HIT: total spend $${totalCost.toFixed(2)} > $${HARD_CAP}. Halting.`);
    process.exit(3);
  }
  if (totalCost > WARN_CAP && !warnLogged) {
    warnLogged = true;
    console.warn(`\nWARNING: total spend $${totalCost.toFixed(2)} > $${WARN_CAP}. Continuing.`);
  }
}

function loadCompleted() {
  if (!existsSync(RESULTS)) return new Set();
  const done = new Set();
  for (const line of readFileSync(RESULTS, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const r = JSON.parse(line);
      done.add(`${r.instance_id}|${r.config}`);
      if (typeof r.total_cost_usd === 'number') totalCost += r.total_cost_usd;
    } catch { /* skip malformed */ }
  }
  return done;
}

let completedCount = 0;
let erroredCount = 0;

async function processTaskConfig(task, config) {
  const row = {
    instance_id: task.instance_id,
    config: config.name,
    executor_model: MODELS[config.executor].slug,
    reviewer_model: config.reviewer ? MODELS[config.reviewer].slug : null,
    executor_input_tokens: 0, executor_output_tokens: 0,
    executor_cost_usd: 0, executor_latency_ms: 0,
    executor_patch: null, executor_diff_parsed: false,
    reviewer_input_tokens: 0, reviewer_output_tokens: 0,
    reviewer_cost_usd: 0, reviewer_latency_ms: 0,
    reviewer_flag: null, reviewer_reason: null,
    reviewer_proposed_fix: null, reviewer_confidence: null,
    revision_input_tokens: 0, revision_output_tokens: 0,
    revision_cost_usd: 0, revision_latency_ms: 0,
    revision_patch: null, revision_diff_parsed: false,
    final_patch: null, total_cost_usd: 0, total_latency_ms: 0,
    errors: [],
  };

  // Executor call.
  try {
    const execResp = await callModel(config.executor, EXEC_SYSTEM,
      buildExecUserPrompt(task, null), EXEC_MAX_TOKENS);
    row.executor_input_tokens = execResp.input_tokens;
    row.executor_output_tokens = execResp.output_tokens;
    row.executor_cost_usd = costOf(MODELS[config.executor].slug,
      execResp.input_tokens, execResp.output_tokens);
    row.executor_latency_ms = execResp.latency_ms;
    row.executor_patch = extractDiff(execResp.text);
    row.executor_diff_parsed = parsesAsDiff(execResp.text);
    row.final_patch = row.executor_patch;
    totalCost += row.executor_cost_usd;
  } catch (e) {
    const msg = String(e.message || e);
    row.errors.push(`executor: ${msg.slice(0, 200)}`);
    if (/credit balance|exceeded your current quota|insufficient_quota|billing/i.test(msg)) {
      console.error(`\nHALT: billing error on executor ${config.executor} at ${task.instance_id}: ${msg.slice(0,200)}`);
      row.total_cost_usd = row.executor_cost_usd;
      appendFileSync(RESULTS, JSON.stringify(row) + '\n');
      process.exit(2);
    }
  }

  // Reviewer + possible revision.
  if (config.reviewer && row.executor_patch && row.executor_diff_parsed) {
    try {
      const revResp = await callModel(config.reviewer, REVIEWER_SYSTEM,
        buildReviewerUserPrompt(task, row.executor_patch), REVIEWER_MAX_TOKENS);
      row.reviewer_input_tokens = revResp.input_tokens;
      row.reviewer_output_tokens = revResp.output_tokens;
      row.reviewer_cost_usd = costOf(MODELS[config.reviewer].slug,
        revResp.input_tokens, revResp.output_tokens);
      row.reviewer_latency_ms = revResp.latency_ms;
      totalCost += row.reviewer_cost_usd;
      const verdict = parseReviewerJson(revResp.text);
      if (verdict) {
        row.reviewer_flag = Boolean(verdict.flag);
        row.reviewer_reason = typeof verdict.reason === 'string' ? verdict.reason.slice(0, 2000) : null;
        row.reviewer_proposed_fix = typeof verdict.proposed_fix === 'string' ? verdict.proposed_fix.slice(0, 4000) : null;
        row.reviewer_confidence = typeof verdict.confidence === 'number' ? verdict.confidence : null;
      } else {
        row.errors.push('reviewer: json parse failed');
      }
    } catch (e) {
      const msg = String(e.message || e);
      row.errors.push(`reviewer: ${msg.slice(0, 200)}`);
      if (/credit balance|exceeded your current quota|insufficient_quota|billing/i.test(msg)) {
        console.error(`\nHALT: billing error on reviewer ${config.reviewer} at ${task.instance_id}: ${msg.slice(0,200)}`);
        row.total_cost_usd = row.executor_cost_usd + row.reviewer_cost_usd;
        appendFileSync(RESULTS, JSON.stringify(row) + '\n');
        process.exit(2);
      }
    }

    if (row.reviewer_flag === true) {
      try {
        const revisionResp = await callModel(config.executor, EXEC_SYSTEM,
          buildExecUserPrompt(task, row.reviewer_reason || '(no reason provided)'),
          EXEC_MAX_TOKENS);
        row.revision_input_tokens = revisionResp.input_tokens;
        row.revision_output_tokens = revisionResp.output_tokens;
        row.revision_cost_usd = costOf(MODELS[config.executor].slug,
          revisionResp.input_tokens, revisionResp.output_tokens);
        row.revision_latency_ms = revisionResp.latency_ms;
        row.revision_patch = extractDiff(revisionResp.text);
        row.revision_diff_parsed = parsesAsDiff(revisionResp.text);
        if (row.revision_patch) row.final_patch = row.revision_patch;
        totalCost += row.revision_cost_usd;
      } catch (e) {
        const msg = String(e.message || e);
        row.errors.push(`revision: ${msg.slice(0, 200)}`);
        if (/credit balance|exceeded your current quota|insufficient_quota|billing/i.test(msg)) {
          console.error(`\nHALT: billing error on revision ${config.executor} at ${task.instance_id}: ${msg.slice(0,200)}`);
          row.total_cost_usd = row.executor_cost_usd + row.reviewer_cost_usd + row.revision_cost_usd;
          appendFileSync(RESULTS, JSON.stringify(row) + '\n');
          process.exit(2);
        }
      }
    }
  }

  row.total_cost_usd = row.executor_cost_usd + row.reviewer_cost_usd + row.revision_cost_usd;
  row.total_latency_ms = row.executor_latency_ms + row.reviewer_latency_ms + row.revision_latency_ms;
  appendFileSync(RESULTS, JSON.stringify(row) + '\n');
  completedCount++;
  if (row.errors.length) erroredCount++;
  const elapsedMin = ((Date.now() - startTime) / 60000).toFixed(1);
  console.log(`[${config.name}] ${task.instance_id}: exec=${row.executor_diff_parsed?'Y':'N'} ` +
    `flag=${row.reviewer_flag} rev=${row.revision_patch?'Y':'N'} ` +
    `$${row.total_cost_usd.toFixed(4)} ${row.total_latency_ms}ms ` +
    `| cum $${totalCost.toFixed(2)} ${elapsedMin}m done=${completedCount}`);
  maybeLogCostMilestones();
}

async function runWorker(workerName, configs, tasks, completed) {
  for (const config of configs) {
    for (const task of tasks) {
      const key = `${task.instance_id}|${config.name}`;
      if (completed.has(key)) continue;
      if (totalCost > HARD_CAP) return;
      await processTaskConfig(task, config);
    }
  }
  console.log(`[worker ${workerName}] done.`);
}

async function main() {
  const tasks = JSON.parse(readFileSync(TASKS_PATH, 'utf8'));
  mkdirSync(join(HARNESS, 'results'), { recursive: true });
  const completed = loadCompleted();
  if (completed.size > 0) {
    console.log(`Resuming: ${completed.size} (task,config) pairs already complete. Cum cost so far: $${totalCost.toFixed(2)}.`);
  }
  const totalPairs = tasks.length * CONFIGS.length;
  console.log(`Target: ${tasks.length} tasks × ${CONFIGS.length} configs = ${totalPairs} pairs. Remaining: ${totalPairs - completed.size}.`);

  // Bucket configs by executor.
  const buckets = {};
  for (const c of CONFIGS) {
    (buckets[c.executor] ||= []).push(c);
  }

  // Periodic summary every 30 minutes.
  const summaryInterval = setInterval(() => {
    const elapsedMin = ((Date.now() - startTime) / 60000).toFixed(1);
    console.log(`[summary] ${elapsedMin}m elapsed, ${completedCount} this session, cum $${totalCost.toFixed(2)}, errors=${erroredCount}`);
  }, 30 * 60 * 1000);

  await Promise.all(Object.entries(buckets).map(([exec, cfgs]) =>
    runWorker(exec, cfgs, tasks, completed)));
  clearInterval(summaryInterval);

  // Final report.
  console.log('\n=== FINAL REPORT ===');
  const rows = readFileSync(RESULTS, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  const byConfig = {};
  for (const r of rows) {
    (byConfig[r.config] ||= []).push(r);
  }
  console.log('config                      | n  | parse% | flag% | revised% | avg_cost | avg_lat');
  console.log('----------------------------|----|--------|-------|----------|----------|--------');
  for (const c of CONFIGS) {
    const rr = byConfig[c.name] || [];
    if (!rr.length) { console.log(`${c.name.padEnd(28)}| 0  | -      | -     | -        | -        | -`); continue; }
    const parsed = rr.filter(r => r.executor_diff_parsed).length;
    const flagged = rr.filter(r => r.reviewer_flag === true).length;
    const revised = rr.filter(r => r.revision_patch).length;
    const avgCost = rr.reduce((s, r) => s + r.total_cost_usd, 0) / rr.length;
    const avgLat = rr.reduce((s, r) => s + r.total_latency_ms, 0) / rr.length;
    const flagStr = c.reviewer ? `${(flagged/rr.length*100).toFixed(0)}%` : '-';
    const revStr  = c.reviewer ? `${(revised/rr.length*100).toFixed(0)}%` : '-';
    console.log(`${c.name.padEnd(28)}| ${rr.length.toString().padStart(2)} | ${(parsed/rr.length*100).toFixed(0).padStart(4)}%  | ${flagStr.padStart(5)} | ${revStr.padStart(8)} | $${avgCost.toFixed(4)} | ${Math.round(avgLat)}ms`);
  }
  console.log(`\nTotal spend: $${totalCost.toFixed(2)}`);
  console.log(`Wall-clock: ${((Date.now() - startTime) / 60000).toFixed(1)} minutes`);
  const errRows = rows.filter(r => r.errors && r.errors.length);
  if (errRows.length) {
    console.log(`\nAnomalies: ${errRows.length} rows with errors.`);
    const errSamples = errRows.slice(0, 5);
    for (const r of errSamples) console.log(`  ${r.instance_id} [${r.config}]: ${r.errors.join('; ').slice(0, 200)}`);
  }
  console.log(`\nEVAL DEFERRED — predictions at results/swebench-full-predictions.jsonl. Run eval on x86 host: dispatch separate prompt tomorrow.`);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
