#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { execSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const TASKS_PATH = path.join(ROOT, 'data/swebench-lite-30tasks.json');
const PRED_PATH = path.join(ROOT, 'results/swebench-full-predictions.jsonl');
const OUT_PATH = path.join(ROOT, 'results/swebench-apply-check.jsonl');
const PTR_PATH = path.join(ROOT, 'results/.swebench-apply-check.ptr');
const REPOS_DIR = '/tmp/swe-repos';
const GEN_PID = 7893;

const log = (msg) => {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  process.stdout.write(line);
};

const sh = (cmd, opts = {}) => spawnSync('bash', ['-c', cmd], { encoding: 'utf8', ...opts });

const tasks = JSON.parse(fs.readFileSync(TASKS_PATH, 'utf8'));
const taskById = new Map(tasks.map((t) => [t.instance_id, t]));

fs.mkdirSync(REPOS_DIR, { recursive: true });

const repoDirFor = (repo) => path.join(REPOS_DIR, repo.replace('/', '__'));
const failedRepos = new Set();

function ensureRepo(repo) {
  const dir = repoDirFor(repo);
  if (failedRepos.has(repo)) return null;
  if (fs.existsSync(path.join(dir, '.git'))) return dir;
  log(`cloning ${repo} -> ${dir}`);
  const r = sh(`git clone --filter=blob:none https://github.com/${repo}.git ${dir}`, { stdio: 'pipe' });
  if (r.status !== 0) {
    log(`CLONE FAILED ${repo}: ${(r.stderr || '').slice(0, 300)}`);
    failedRepos.add(repo);
    return null;
  }
  return dir;
}

function pruneIfOverBudget() {
  try {
    const out = sh(`du -sk ${REPOS_DIR} 2>/dev/null | awk '{print $1}'`).stdout.trim();
    const kb = parseInt(out || '0', 10);
    if (kb > 20 * 1024 * 1024) {
      log(`repo dir ${Math.round(kb / 1024)}MB over budget, pruning oldest`);
      const entries = fs.readdirSync(REPOS_DIR).map((n) => {
        const p = path.join(REPOS_DIR, n);
        return { p, mtime: fs.statSync(p).mtimeMs };
      }).sort((a, b) => a.mtime - b.mtime);
      if (entries.length) {
        sh(`rm -rf ${entries[0].p}`);
        log(`pruned ${entries[0].p}`);
      }
    }
  } catch {}
}

function checkPatch(task, patch) {
  const dir = ensureRepo(task.repo);
  if (!dir) return { applies_cleanly: false, git_apply_stderr: 'repo clone failed' };
  const co = sh(`git -C ${dir} checkout -q --force ${task.base_commit} 2>&1`);
  if (co.status !== 0) {
    const fetch = sh(`git -C ${dir} fetch --depth=1 origin ${task.base_commit} 2>&1`);
    if (fetch.status === 0) sh(`git -C ${dir} checkout -q --force ${task.base_commit}`);
  }
  const patchFile = `/tmp/apply-check-${process.pid}.patch`;
  fs.writeFileSync(patchFile, patch);
  const r = sh(`git -C ${dir} apply --check ${patchFile} 2>&1`);
  fs.unlinkSync(patchFile);
  return {
    applies_cleanly: r.status === 0,
    git_apply_stderr: r.status === 0 ? '' : (r.stdout + r.stderr).slice(0, 500),
  };
}

function readPtr() {
  try { return parseInt(fs.readFileSync(PTR_PATH, 'utf8').trim(), 10) || 0; } catch { return 0; }
}
function writePtr(n) { fs.writeFileSync(PTR_PATH, String(n)); }

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

let processed = 0;
let applies = 0;
const perConfig = new Map();

function processNew() {
  if (!fs.existsSync(PRED_PATH)) return;
  const lines = fs.readFileSync(PRED_PATH, 'utf8').split('\n').filter(Boolean);
  const start = readPtr();
  if (lines.length <= start) return;
  for (let i = start; i < lines.length; i++) {
    let row;
    try { row = JSON.parse(lines[i]); } catch { writePtr(i + 1); continue; }
    const task = taskById.get(row.instance_id);
    if (!task) { writePtr(i + 1); continue; }
    const hasRevision = row.revision_patch && row.revision_diff_parsed;
    const patch = hasRevision ? row.revision_patch : row.executor_patch;
    const patchSource = hasRevision ? 'revision' : 'executor';
    let result;
    if (!patch) {
      result = { applies_cleanly: false, git_apply_stderr: 'no patch' };
    } else {
      result = checkPatch(task, patch);
    }
    const out = {
      instance_id: row.instance_id,
      config: row.config,
      applies_cleanly: result.applies_cleanly,
      git_apply_stderr: result.git_apply_stderr,
      patch_length_chars: patch ? patch.length : 0,
      patch_source: patchSource,
    };
    fs.appendFileSync(OUT_PATH, JSON.stringify(out) + '\n');
    writePtr(i + 1);
    processed++;
    if (result.applies_cleanly) applies++;
    const cfg = perConfig.get(row.config) || { n: 0, ok: 0 };
    cfg.n++; if (result.applies_cleanly) cfg.ok++;
    perConfig.set(row.config, cfg);
    log(`[${row.config}] ${row.instance_id}: applies=${result.applies_cleanly ? 'Y' : 'N'}`);
    if (processed % 30 === 0) {
      log(`SUMMARY processed=${processed} applies=${applies}`);
      for (const [c, v] of perConfig) log(`  ${c}: ${v.ok}/${v.n}`);
    }
    pruneIfOverBudget();
  }
}

function totalLines() {
  try { return fs.readFileSync(PRED_PATH, 'utf8').split('\n').filter(Boolean).length; } catch { return 0; }
}

async function main() {
  log(`apply-check starting. watching ${PRED_PATH}`);
  // Pre-clone unique repos
  const uniq = [...new Set(tasks.map((t) => t.repo))];
  for (const r of uniq) ensureRepo(r);

  // Main poll loop
  while (true) {
    processNew();
    const alive = pidAlive(GEN_PID);
    const ptr = readPtr();
    const total = totalLines();
    if (!alive && ptr >= total) break;
    await new Promise((r) => setTimeout(r, 30_000));
  }

  // Final report
  log('=== FINAL REPORT ===');
  const configs = [
    'solo-claude', 'solo-gpt', 'solo-gemini',
    'claude-reviews-gpt', 'gpt-reviews-gemini', 'gemini-reviews-claude',
  ];
  const reports = {};
  for (const c of configs) {
    const v = perConfig.get(c) || { n: 0, ok: 0 };
    reports[c] = v;
    const pct = v.n ? Math.round((v.ok / v.n) * 100) : 0;
    log(`${c}: ${v.ok}/${v.n} apply cleanly (${pct}%)`);
  }
  log('--- Cross-family uplift (reviewer config vs solo executor) ---');
  const pairs = [
    ['claude-reviews-gpt', 'solo-gpt'],
    ['gpt-reviews-gemini', 'solo-gemini'],
    ['gemini-reviews-claude', 'solo-claude'],
  ];
  for (const [rev, solo] of pairs) {
    const r = reports[rev]; const s = reports[solo];
    const rRate = r.n ? r.ok / r.n : 0;
    const sRate = s.n ? s.ok / s.n : 0;
    const delta = Math.round((rRate - sRate) * 100);
    log(`${rev} vs ${solo}: ${Math.round(rRate * 100)}% vs ${Math.round(sRate * 100)}% (delta=${delta >= 0 ? '+' : ''}${delta}pp)`);
  }
  log('=== DONE ===');
}

main().catch((e) => { log(`FATAL ${e.stack || e.message}`); process.exit(1); });
