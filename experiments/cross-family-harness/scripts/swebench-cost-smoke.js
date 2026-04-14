// swebench-cost-smoke.js — cost-only calibration on SWE-bench-lite.
// No repo clone, no patch apply, no test execution. Prompt each model,
// record tokens/cost/latency, check if response parses as a unified diff.
// Usage: node scripts/swebench-cost-smoke.js

import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HARNESS = join(__dirname, '..');
const TASKS_PATH = join(HARNESS, 'data', 'swebench-lite-5tasks.json');
const RESULTS = join(HARNESS, 'results', 'swebench-cost-smoke.jsonl');

const envPath = join(HARNESS, '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) process.env[m[1]] = m[2];
  }
}

const PRICING = {
  'claude-opus-4-6':           { input: 15.0, output: 75.0 },
  'gpt-5.4':                   { input: 5.0,  output: 20.0 },
  'gemini-3.1-pro-preview':    { input: 2.5,  output: 10.0 },
};

const MODELS = [
  { id: 'claude', slug: 'claude-opus-4-6',          provider: 'anthropic' },
  { id: 'gpt',    slug: 'gpt-5.4',                  provider: 'openai' },
  { id: 'gemini', slug: 'gemini-3.1-pro-preview',   provider: 'google' },
];

const SYSTEM_PROMPT = 'You are a software engineer. Produce a unified diff patch that fixes the described bug. Output ONLY the diff, no explanation, no markdown fences.';

function buildUserPrompt(task) {
  let s = `Repo: ${task.repo}\nBase commit: ${task.base_commit}\n\nIssue:\n${task.problem_statement}\n\n`;
  if (task.hints_text && task.hints_text.length) s += `Hints:\n${task.hints_text}\n\n`;
  s += 'Produce the unified diff:';
  return s;
}

function parsesAsDiff(text) {
  if (!text) return false;
  const t = text.trim();
  const startsOk = /^(diff --git|---\s)/m.test(t.slice(0, 200));
  const hasPlus = /^\+\+\+\s/m.test(t);
  const hasHunk = /^@@\s/m.test(t);
  return startsOk && hasPlus && hasHunk;
}

async function callAnthropic(slug, system, user) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();
  const start = Date.now();
  const r = await client.messages.create({
    model: slug, max_tokens: 4096, system,
    messages: [{ role: 'user', content: user }],
  });
  return {
    text: r.content.map(c => c.text || '').join(''),
    input_tokens: r.usage.input_tokens,
    output_tokens: r.usage.output_tokens,
    latency_ms: Date.now() - start,
  };
}

async function callOpenAI(slug, system, user) {
  const { default: OpenAI } = await import('openai');
  const client = new OpenAI();
  const start = Date.now();
  let r;
  try {
    r = await client.chat.completions.create({
      model: slug, max_completion_tokens: 4096,
      messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
    });
  } catch (e) {
    r = await client.chat.completions.create({
      model: slug, max_tokens: 4096,
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

async function callGoogle(slug, system, user) {
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

async function callModel(model, system, user) {
  if (model.provider === 'anthropic') return callAnthropic(model.slug, system, user);
  if (model.provider === 'openai')    return callOpenAI(model.slug, system, user);
  if (model.provider === 'google')    return callGoogle(model.slug, system, user);
  throw new Error('unknown provider');
}

function cost(slug, inTok, outTok) {
  const p = PRICING[slug];
  return (inTok * p.input + outTok * p.output) / 1_000_000;
}

async function main() {
  const tasks = JSON.parse(readFileSync(TASKS_PATH, 'utf8'));
  mkdirSync(join(HARNESS, 'results'), { recursive: true });
  writeFileSync(RESULTS, '');
  const rows = [];
  let totalCost = 0;

  for (const task of tasks) {
    const system = SYSTEM_PROMPT;
    const user = buildUserPrompt(task);
    for (const model of MODELS) {
      let row = {
        task_id: task.instance_id, config: model.id, slug: model.slug,
        input_tokens: 0, output_tokens: 0, cost_usd: 0, latency_ms: 0,
        response_length_chars: 0, diff_parses: false,
        parse_error: false, api_error: null,
      };
      try {
        const resp = await callModel(model, system, user);
        row.input_tokens = resp.input_tokens;
        row.output_tokens = resp.output_tokens;
        row.latency_ms = resp.latency_ms;
        row.cost_usd = cost(model.slug, resp.input_tokens, resp.output_tokens);
        row.response_length_chars = (resp.text || '').length;
        row.diff_parses = parsesAsDiff(resp.text);
        if (!row.diff_parses) row.parse_error = true;
        totalCost += row.cost_usd;
      } catch (e) {
        row.api_error = String(e.message || e).slice(0, 300);
        const msg = row.api_error.toLowerCase();
        if (/credit balance|exceeded your current quota|insufficient_quota|billing/.test(msg)) {
          rows.push(row);
          appendFileSync(RESULTS, JSON.stringify(row) + '\n');
          console.error(`\nHALT: billing error on ${model.id} (${model.slug}) at ${task.instance_id}`);
          console.error(`  -> ${row.api_error}`);
          process.exit(2);
        }
      }
      rows.push(row);
      appendFileSync(RESULTS, JSON.stringify(row) + '\n');
      console.log(`[${model.id}] ${task.instance_id}: in=${row.input_tokens} out=${row.output_tokens} ` +
        `$${row.cost_usd.toFixed(4)} ${row.latency_ms}ms diff=${row.diff_parses}` +
        (row.api_error ? ` ERR: ${row.api_error}` : ''));
    }
  }

  console.log('\n=== SUMMARY ===');
  console.log('model                      | avg_in | avg_out | avg_cost | avg_latency | diff_parse');
  console.log('---------------------------|--------|---------|----------|-------------|-----------');
  const perModel = {};
  for (const m of MODELS) {
    const mr = rows.filter(r => r.config === m.id && !r.api_error);
    const n = mr.length || 1;
    const avgIn = mr.reduce((s, r) => s + r.input_tokens, 0) / n;
    const avgOut = mr.reduce((s, r) => s + r.output_tokens, 0) / n;
    const avgCost = mr.reduce((s, r) => s + r.cost_usd, 0) / n;
    const avgLat = mr.reduce((s, r) => s + r.latency_ms, 0) / n;
    const parses = mr.filter(r => r.diff_parses).length;
    perModel[m.id] = { avgCost, avgLat, parses, n: mr.length };
    console.log(`${m.slug.padEnd(26)} | ${Math.round(avgIn).toString().padStart(6)} | ${Math.round(avgOut).toString().padStart(7)} | $${avgCost.toFixed(4)} | ${Math.round(avgLat).toString().padStart(9)}ms | ${parses}/${mr.length}`);
  }

  const blended = (perModel.claude.avgCost + perModel.gpt.avgCost + perModel.gemini.avgCost) / 3;
  const claudeHeavy = perModel.claude.avgCost;
  const CALL_VOLUME = 1350;
  const blendedFull = blended * CALL_VOLUME;
  const highFull = claudeHeavy * CALL_VOLUME;

  console.log(`\nCOST/CALL: Claude=$${perModel.claude.avgCost.toFixed(4)}, GPT=$${perModel.gpt.avgCost.toFixed(4)}, Gemini=$${perModel.gemini.avgCost.toFixed(4)}. Blended avg=$${blended.toFixed(4)}.`);
  console.log(`\nEXTRAPOLATED 50-TASK x 9-CONFIG RUN:`);
  console.log(`  Call volume: 50 tasks × 9 configs × 3 calls/config avg = 1,350 calls.`);
  console.log(`  Blended-avg cost: $${blendedFull.toFixed(2)}   (using smoke blended avg)`);
  console.log(`  Claude-heavy cost: $${highFull.toFixed(2)}  (using Claude per-call × 1,350, upper bound)`);
  console.log(`  Configs breakdown:`);
  console.log(`    3 solo (1 call each): 150 calls`);
  console.log(`    6 cross-family (2-3 calls each): 900-1,350 calls`);
  console.log(`    (Note: no same-family, no triangulated in this scope)`);
  console.log(`\nDIFF-PARSE RATE (weak proxy for harness readiness):`);
  console.log(`  Claude ${perModel.claude.parses}/${perModel.claude.n}, GPT ${perModel.gpt.parses}/${perModel.gpt.n}, Gemini ${perModel.gemini.parses}/${perModel.gemini.n}`);

  console.log(`\nTotal smoke spend: $${totalCost.toFixed(4)}`);
  if (highFull < 150) {
    console.log(`\nSMOKE GREEN — commit full run at 50 tasks × 9 configs. (upper-bound extrapolation $${highFull.toFixed(0)})`);
  } else if (highFull <= 300) {
    console.log(`\nSCOPE-DOWN NEEDED — extrapolates to $${highFull.toFixed(0)} at 50 tasks, recommend 30 tasks or 6 configs.`);
  } else {
    console.log(`\nCOST REVIEW — extrapolates to $${highFull.toFixed(0)}, needs Tima call.`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
