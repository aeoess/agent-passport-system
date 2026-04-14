// smoke-quixbugs.js — 10-task saturation probe across three frontier models.
// Usage: node scripts/smoke-quixbugs.js
// Reads .env in harness dir. Writes results/smoke-quixbugs.jsonl and prints summary.

import { readFileSync, writeFileSync, existsSync, mkdirSync, appendFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HARNESS = join(__dirname, '..');
const QB = join(HARNESS, 'data', 'quixbugs');
const RESULTS = join(HARNESS, 'results', 'smoke-quixbugs-hard.jsonl');

// Load .env
const envPath = join(HARNESS, '.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) process.env[m[1]] = m[2];
  }
}

// Pricing per 1M tokens (approximate, April 2026).
const PRICING = {
  'claude-opus-4-6': { input: 15.0, output: 75.0 },
  'gpt-5.4':         { input: 5.0,  output: 20.0 },
  'gemini-3.1-pro-preview': { input: 2.5, output: 10.0 },
};

const TASKS = [
  'levenshtein', 'knapsack', 'lcs_length', 'longest_common_subsequence',
  'shortest_paths', 'quicksort', 'sieve', 'kth', 'rpn_eval', 'mergesort',
];

const MODELS = [
  { id: 'claude', slug: 'claude-opus-4-6', provider: 'anthropic' },
  { id: 'gpt',    slug: 'gpt-5.4',          provider: 'openai' },
  { id: 'gemini', slug: 'gemini-3.1-pro-preview', provider: 'google' },
];

function extractCode(text) {
  if (!text) return null;
  const fence = text.match(/```(?:python|py)?\s*\n([\s\S]*?)```/);
  if (fence) return fence[1].trim();
  // No fence — assume whole thing is code.
  return text.trim();
}

function makePrompt(taskId, buggySource) {
  return `The following Python function has exactly one bug. Fix it and return ONLY the corrected Python code, wrapped in a single \`\`\`python code block. Do not include any explanation, tests, or docstrings beyond what is already present. Preserve the function signature and module-level structure.

Task: ${taskId}

\`\`\`python
${buggySource}
\`\`\``;
}

async function callAnthropic(slug, prompt) {
  const { default: Anthropic } = await import('@anthropic-ai/sdk');
  const client = new Anthropic();
  const start = Date.now();
  const r = await client.messages.create({
    model: slug, max_tokens: 2048,
    messages: [{ role: 'user', content: prompt }],
  });
  return {
    text: r.content.map(c => c.text || '').join(''),
    input_tokens: r.usage.input_tokens,
    output_tokens: r.usage.output_tokens,
    latency_ms: Date.now() - start,
  };
}

async function callOpenAI(slug, prompt) {
  const { default: OpenAI } = await import('openai');
  const client = new OpenAI();
  const start = Date.now();
  // gpt-5.x uses Responses API or Chat Completions with max_completion_tokens
  let r;
  try {
    r = await client.chat.completions.create({
      model: slug,
      max_completion_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });
  } catch (e) {
    // Fallback to legacy max_tokens
    r = await client.chat.completions.create({
      model: slug, max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });
  }
  return {
    text: r.choices[0].message.content || '',
    input_tokens: r.usage.prompt_tokens,
    output_tokens: r.usage.completion_tokens,
    latency_ms: Date.now() - start,
  };
}

async function callGoogle(slug, prompt) {
  const { GoogleGenerativeAI } = await import('@google/generative-ai');
  const genAI = new GoogleGenerativeAI(process.env.GOOGLE_AI_API_KEY);
  const model = genAI.getGenerativeModel({ model: slug });
  const start = Date.now();
  const result = await model.generateContent(prompt);
  const response = result.response;
  const usage = response.usageMetadata || {};
  return {
    text: response.text(),
    input_tokens: usage.promptTokenCount || 0,
    output_tokens: usage.candidatesTokenCount || 0,
    latency_ms: Date.now() - start,
  };
}

async function callModel(model, prompt) {
  if (model.provider === 'anthropic') return callAnthropic(model.slug, prompt);
  if (model.provider === 'openai')    return callOpenAI(model.slug, prompt);
  if (model.provider === 'google')    return callGoogle(model.slug, prompt);
  throw new Error('unknown provider');
}

function cost(slug, inTok, outTok) {
  const p = PRICING[slug];
  return (inTok * p.input + outTok * p.output) / 1_000_000;
}

function runTests(taskId, fixedCode) {
  const progPath = join(QB, 'python_programs', `${taskId}.py`);
  const original = readFileSync(progPath, 'utf8');
  let tests_passed = 0, tests_total = 0, stderr = '';
  try {
    writeFileSync(progPath, fixedCode);
    const testFile = join('python_testcases', `test_${taskId}.py`);
    const r = spawnSync('python3',
      ['-m', 'pytest', testFile, '--timeout=5', '--tb=no', '-q', '--no-header'],
      { cwd: QB, encoding: 'utf8', timeout: 120_000 });
    const out = (r.stdout || '') + (r.stderr || '');
    stderr = r.stderr?.slice(0, 500) || '';
    // Parse "N passed" / "N failed" from last lines.
    const passMatch = out.match(/(\d+)\s+passed/);
    const failMatch = out.match(/(\d+)\s+failed/);
    const errorMatch = out.match(/(\d+)\s+error/);
    const p = passMatch ? parseInt(passMatch[1]) : 0;
    const f = failMatch ? parseInt(failMatch[1]) : 0;
    const e = errorMatch ? parseInt(errorMatch[1]) : 0;
    tests_passed = p;
    tests_total = p + f + e;
    if (tests_total === 0) {
      // Collection failed (syntax error etc.)
      tests_total = 1;
      tests_passed = 0;
      stderr = out.slice(-500);
    }
  } finally {
    writeFileSync(progPath, original);
  }
  return { tests_passed, tests_total, stderr };
}

async function main() {
  mkdirSync(join(HARNESS, 'results'), { recursive: true });
  writeFileSync(RESULTS, ''); // truncate
  const rows = [];
  let totalCost = 0;

  for (const taskId of TASKS) {
    const buggy = readFileSync(join(QB, 'python_programs', `${taskId}.py`), 'utf8');
    const prompt = makePrompt(taskId, buggy);

    for (const model of MODELS) {
      let row = {
        task_id: taskId, config: model.id, slug: model.slug,
        input_tokens: 0, output_tokens: 0, cost_usd: 0, latency_ms: 0,
        tests_passed: 0, tests_total: 0, parse_error: false, api_error: null,
      };
      try {
        const resp = await callModel(model, prompt);
        row.input_tokens = resp.input_tokens;
        row.output_tokens = resp.output_tokens;
        row.latency_ms = resp.latency_ms;
        row.cost_usd = cost(model.slug, resp.input_tokens, resp.output_tokens);
        totalCost += row.cost_usd;
        const code = extractCode(resp.text);
        if (!code || code.length < 10) {
          row.parse_error = true;
        } else {
          const t = runTests(taskId, code);
          row.tests_passed = t.tests_passed;
          row.tests_total = t.tests_total;
        }
      } catch (e) {
        row.api_error = String(e.message || e).slice(0, 300);
        const msg = row.api_error.toLowerCase();
        const billing = /credit balance|exceeded your current quota|insufficient_quota|billing/.test(msg);
        if (billing) {
          rows.push(row);
          appendFileSync(RESULTS, JSON.stringify(row) + '\n');
          console.error(`\nHALT: billing error on ${model.id} (${model.slug}) at task ${taskId}`);
          console.error(`  -> ${row.api_error}`);
          console.error(`  Not burning budget on remaining accounts. Report and exit.`);
          process.exit(2);
        }
      }
      rows.push(row);
      appendFileSync(RESULTS, JSON.stringify(row) + '\n');
      console.log(`[${model.id}] ${taskId}: ${row.tests_passed}/${row.tests_total} ` +
        `($${row.cost_usd.toFixed(4)}, ${row.latency_ms}ms)` +
        (row.api_error ? ` ERR: ${row.api_error}` : '') +
        (row.parse_error ? ' PARSE_ERR' : ''));
    }
  }

  console.log('\n=== SUMMARY ===');
  console.log('model                      | pass_rate | avg_cost | avg_latency | parse_err | api_err');
  console.log('---------------------------|-----------|----------|-------------|-----------|--------');
  const rates = {};
  for (const model of MODELS) {
    const mr = rows.filter(r => r.config === model.id);
    const fullyPassed = mr.filter(r => r.tests_total > 0 && r.tests_passed === r.tests_total && !r.parse_error && !r.api_error).length;
    const rate = fullyPassed / TASKS.length;
    rates[model.id] = rate;
    const avgCost = mr.reduce((s, r) => s + r.cost_usd, 0) / mr.length;
    const avgLat  = mr.reduce((s, r) => s + r.latency_ms, 0) / mr.length;
    const parseErrs = mr.filter(r => r.parse_error).length;
    const apiErrs = mr.filter(r => r.api_error).length;
    console.log(`${model.slug.padEnd(26)} | ${(rate*100).toFixed(1).padStart(7)}%  | $${avgCost.toFixed(4)} | ${Math.round(avgLat).toString().padStart(9)}ms | ${parseErrs.toString().padStart(9)} | ${apiErrs}`);
  }
  console.log(`\nTotal spend: $${totalCost.toFixed(4)}`);
  const maxRate = Math.max(...Object.values(rates));
  const pct = (maxRate*100).toFixed(1);
  if (maxRate > 0.90) {
    console.log(`\nSATURATION CONFIRMED — pivot to SWE-bench-lite. (max pass_rate = ${pct}%)`);
  } else if (maxRate >= 0.60) {
    console.log(`\nQUIXBUGS-HARD VIABLE — proceed with full run on this subset. (max pass_rate = ${pct}%)`);
  } else {
    console.log(`\nAMBIGUOUS — investigate. (max pass_rate = ${pct}%)`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
