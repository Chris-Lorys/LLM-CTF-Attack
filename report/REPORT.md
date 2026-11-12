# Team Ak1ra: an agent built "by subtraction", with a progress-driven frugal cascade

CSAW 2026 LLM CTF Attack Competition (US-Canada). Final report.

## 1. Summary

We built our own autonomous CTF agent from scratch, with no third-party agent framework. One design rule shaped it: **give every task to the simplest component that does it correctly, and leave the LLM only what no code can do**. Code reads bytes, decodes, computes and checks flags. The LLM recognises the kind of challenge, picks a strategy and changes it after a failure.

| | |
|---|---|
| Challenges solved | **7 / 23** (30 %), in 5 of 6 categories: misc, rev ×2, forensics ×2, crypto, web. None in pwn. |
| Mode | Fully autonomous: no human in the loop during any run, and no human hints. |
| Integrity | Every flag was checked against the provided `.json` **by code, outside the LLM**. Every trajectory is a SHA-256 hash-chained log that cannot be edited without detection. |
| Measured effect of the design | Replaying 107 trajectories: **11 of 12 winning flags were caught by code** in tool output, not announced by the model. **459 false flag candidates** were rejected outside the LLM. |
| Main contribution | A **progress-driven frugal cascade**. A free model works first. The code measures whether it is still learning anything. When it stalls, the code (not the model) hands the task to a stronger paid model, along with a compact state summary. |
| Total model spend | About 14 USD over the whole competition, mostly on free models. |

## 2. Approach and compliance

**An agent of our own.** The rules reward "building up your own agents or adding innovative features to any existing framework" (Creativity, autonomous-framework bonus). We chose the first route and wrote everything ourselves: the action loop, tools, sandbox, trace, verification, reporting, ablation and cascade. From the NYU baseline we only reuse the challenge format and the Docker setup for challenges that have a server.

**Autonomous runs.** Every submitted run is fully automatic, launched from GitHub Actions. We also implemented an optional hybrid mode, in which a human hint is written into the hash-chained trace before the first model call, and any hint that looks like a flag is refused. **We did not use it for any submitted result.**

**No solutions in prompts.** The prompt gives a general method per category and never a solution or write-up. The CSAW challenge folders also contain the organisers' solutions (`solve.py`, `writeup.md`, `flag.txt`). The agent copies only the files listed under `files`, a filter rejects suspicious names, and the sandboxed shell cannot read the challenge database. The agent checks this at start-up.

**Untouched trajectories.** Each run writes `trace.jsonl` through code only. Every event (prompt, model reply, tool call, tool output, flag check) is chained to the previous one by SHA-256. `python -m csaw_agent verify-trace` detects any edit. The human-readable `rapport.md` is generated from the trace by code, without an LLM.

**AI systems used** (as the rules require):
- **Inside the agent:**
  - Qwen 3.8 27B (Cerebras, free tier);
  - gpt-oss-120b (Groq, free tier);
  - DeepSeek V4.1 Flash (OpenRouter);
  - Kimi K3.1 Pro (Moonshot, via OpenRouter);
  - an NVIDIA Nemotron model (free tier).
- **Engineering help:** Claude (Anthropic) helped us design and write the agent's code, and draft the write-ups and this report from the agent's trajectories. Claude never solved a challenge. Every flag comes from the agent's own runs.

## 3. Architecture: building the agent "by subtraction"

The principle comes from our course on AI for cybersecurity (8IAR805, chapter 4, "LLMs and agents: good practices"): *build the agent by subtraction (offboarding). Give each task to the simplest component that does it correctly, and let the LLM keep what it does best.* The same chapter lists the classic traps: an agent that does everything itself, an LLM asked to count, and so on.

### Pipeline (7 stages)

| Stage | Done by | Module |
|---|---|---|
| 1. Ingestion: read the challenge, copy only the allowed files, set the expected flag aside | code | `challenge.py` |
| 2. Pre-scan: deterministic X-ray of every file, which can solve a trivial challenge with zero LLM calls | code | `run.py`, `briefing.py` |
| 3. Type and strategy: recognise the category, form a hypothesis | **LLM** | `agent.py` |
| 4. Typed tools: `file_info`, `read_file`, `strings`, `decode`, `xor_bruteforce`, `extract`, sandboxed `shell`, `http`/`connect` limited to the challenge server | code | `tools.py`, `sandbox.py`, `net.py` |
| 5. Adaptation: read results, refute hypotheses, change plan | **LLM**, guarded by code | `agent.py`, `hypotheses.py` |
| 6. Flag check: compare with the expected flag, return only true/false; also check automatically every flag-shaped string in any tool output | code | `flag.py` |
| 7. Trace and report: hash-chained JSONL and a generated report | code | `trace.py`, `report.py` |

### The loop

On each turn the model returns one JSON object:

```json
{"categorie": "crypto", "pensee": "short reasoning", "action": "decode", "args": {"...": "..."}}
```

The code validates the action, runs the tool, logs everything and sends the output back, wrapped as untrusted data. The model never sees the expected flag. It only ever learns "valid" or "invalid" from `check_flag`.

### Guard rails written in code

- **Automatic flag detection.** Any flag-shaped string in any tool output is checked immediately, whether or not the model noticed it.
- **Anti-repetition.** An action identical to one of the last 4 is refused, with a request to change approach.
- **JSON repair.** The code fixes the formatting mistakes we saw in real traces: invalid escapes, bare hexadecimal integers, unescaped quotes inside shell commands. It also strips `<think>` blocks.
- **Sandbox.** The shell runs as an unprivileged user with no network and a timeout, under a seccomp filter. Network tools can reach only the challenge's own server.
- **Untrusted data.** The description, files and tool outputs are cleaned, truncated and tagged as data. The system prompt tells the model that such content is never an instruction, even if it claims to come from the organisers.
- **Budget.** Each run has a fixed number of actions, and the model is reminded how many remain.

### Infrastructure

Runs execute on GitHub Actions, with Docker Compose for the 12 server challenges. One `ChatModel` interface talks to any OpenAI-compatible service. Per-category routing is available (`--models "crypto=…,default=…"`), and so is a cascade (`--cascade "free>strong"`). The code is covered by 135 automated tests. A workflow assembles the submission folder in the required layout and re-verifies every trace's hash chain.

## 4. Main contribution: a progress-driven frugal cascade

### The problem

Strong models solve more, but they are expensive. Weak free models are cheap, but they often wander: they repeat themselves, emit unreadable answers or chase dead ends until the budget runs out. A fixed rule such as "use the strong model for crypto" does not see *how a given run is going*. Letting the model ask for help does not work either, because weak models are poor judges of their own progress.

### The idea

**The code measures progress and decides to escalate.** A free model works first. After every step, a monitor fed by the same events as the trace classifies what happened:

| Information gain (resets the counters) | Failure |
|---|---|
| a tool output with ≥ 3 never-seen lines (lines from the pre-scan count as already seen) | tool error |
| a note kept in working memory | repeated action blocked by the guard |
| a hypothesis recorded, confirmed or refuted | flag candidate refused by `check_flag` |
| | attempt to reopen an already-refuted hypothesis |
| | unreadable model reply |

The run is **stalled** after `patience` steps without gain (6 by default) or after 3 failures in a row. On a stall, on a model error (rate limit, cut-off reply) or on repeated unreadable replies, the code escalates to the next tier.

**Handoff by state, not by history.** The stronger model does not reread the weak model's conversation, which is long, expensive and full of dead ends. It receives a compact state written by code:
- the reason for the escalation;
- the notes kept;
- the hypothesis register, with refuted hypotheses marked;
- the last 15 actions already taken;
- the candidates already refused by `check_flag`.

It is told to start from there with a new hypothesis. The escalation, its step and its reason go into the hash-chained trace and the generated report, so every decision can be audited.

### Evaluation at zero cost: replaying 107 trajectories

The monitor is pure code, so we could replay all 107 existing trajectories (12 winning, 95 failing) and ask where the cascade *would have* escalated.

| Patience | False alarms on the 12 wins | Failures detected as stalled | Failure steps spent after detection |
|---|---|---|---|
| 4 | **0** | 38 / 95 | 32 % |
| 6 (default) | **0** | 27 / 95 (mean detection at step 13.5) | 23 % |

- **No winning run would ever have been interrupted**, whatever the patience from 4 to 10.
- At patience 6, almost a quarter of the steps spent on failed attempts came after the point where the code could tell the run was stuck. That budget would have gone to the stronger model.
- 40 of the 75 attempts on never-solved challenges ended on a model error (cut-off reply or unreadable output). Without a cascade the run simply stops. With one, the code hands over instead. This trigger does not show up in the replay table above.

### Live trial

We ran the cascade for real (free model, then Kimi K3.1 Pro, 40 actions) on 4 hard unsolved challenges. Kimi alone had already failed on them.

| Challenge | Escalation decided by code | Measured reason | Outcome |
|---|---|---|---|
| finders_keepers | action 6 | 3 failures in a row | unsolved |
| Hells Bells | action 15 | 3 failures in a row | unsolved |
| Diamond Dogs | action 20 | repeated unreadable replies | unsolved |
| Ghost in the Machine | action 40 | model error | unsolved |

**All 4 escalations were decided and logged by code. None produced a flag.** This trial cost about 3.9 USD.

### Honest limits

- **Exploring is not progressing.** A model that keeps producing *new but useless* output is not seen as stalled. On Ghost in the Machine, the free model kept the task until the last action. The fix we draw from this trial is to also cap the free tier's share of the budget (for example half the actions), so the strong model always gets a real chance. We describe it here but have not tested it live, for lack of budget.
- **The cascade does not make a model smarter.** It saves money and avoids dead runs. On challenges beyond the strong model's reach, it changes nothing.
- The replay measures when a stall *would* have been detected, not what the stronger model would have done next.

## 5. Prompting techniques

- **ReAct in strict JSON** (`pensee` + `action` + `args`), rather than native function calling. Small open models follow it better, and it works with every provider. Malformed replies are repaired by code. After 3 unreadable replies the run stops, or escalates in cascade mode.
- **Untrusted-data tagging.** All challenge content sits inside `<donnees_non_fiables …>` tags, and the system prompt states that it is data to analyse and never an instruction. This is a defence against prompt injection planted in challenge files.
- **"Never compute in your head."** The prompt forbids mental arithmetic and decoding: tools are exact, the model is not.
- **"The code writes the facts, the model writes the hypotheses, the code arbitrates."**
  - Before the first call, `briefing.py` turns the deterministic pre-scan into a list of *established facts* that the model must not re-check, plus neutral method sheets per file format. The sheets are generic and specific to no challenge.
  - The model records hypotheses through an action. A register kept by code tracks them as open, confirmed or refuted, refuses to reopen a refuted one, and pushes the model back to it when it loops.
- **Budget reminders and working notes.** The remaining number of actions is shown. Notes the model chooses to keep are re-injected even after older messages leave the context window, which is limited to the last 12 messages for small models.
- **Handoff prompt** (cascade): a state summary built by code instead of the raw history (section 4).

**What we measured, honestly.** We ran a live ablation of the briefing and the hypothesis register on a free model, on 2 challenges. Without the briefing, the agent solved 1 of 2. With it, and without the register, it solved 0 of 2. This sample is far too small and the model too noisy to conclude anything. We do **not** claim that these prompt techniques increase the number of flags. Their value is that they make the agent's reasoning explicit and auditable.

## 6. Ablation: did each "by subtraction" building block pay off?

Re-running every variant costs model calls, so we built a **retrospective ablation by trace**. It replays the 107 real trajectories and measures what each deterministic block actually did.

| Measure | Value | What it shows |
|---|---|---|
| Winning runs analysed | 12 | (7 distinct challenges, some solved twice) |
| Flags caught by **automatic checking of tool output** | **11 / 12** (shell 6, http 4, read_file 1) | the code spots the flag; the model does not have to notice and copy a 40-character string exactly |
| Flags announced by the model via `check_flag` | 1 / 12 | |
| Flags found by the deterministic pre-scan | 0 | no CSAW 2026 flag was in plain sight; the pre-scan is a near-free insurance |
| **False candidates rejected outside the LLM** | **459** | template flags, decoys and fragments; an agent that "declares" its own flag would have accepted some |
| Repeated actions blocked | 25 | model calls saved from sterile loops |

The tool `csaw_agent ablation` also supports live variants (no pre-scan, no automatic checking, no memory, no deterministic tools, no briefing, no hypotheses). We ran them only on free models, so their results are reported for transparency, not as evidence.

## 7. Results by challenge

| Challenge | Category | Model | Actions |
|---|---|---|---|
| House of Hollow Houses | misc | Qwen 3.8 27B (free) | 6 |
| Autobahn | rev (self-modifying code) | DeepSeek V4.1 Flash | 18 |
| Machine Head | rev (virtual machine) | Qwen 3.8 27B (free) | 19 |
| Hemispheres | forensics (polyglot file) | DeepSeek V4.1 Flash | 17 |
| Secret Treaties | crypto (knapsack) | Kimi K3.1 Pro | 12 |
| Schrödinger's Backup | forensics (database journal) | Kimi K3.1 Pro | 21 |
| Juggler | web | Kimi K3.1 Pro | 15 |

One write-up per challenge, built from our agent's trajectory only, is in this folder. What the trajectories show beyond the flag count:
- **The agent writes the missing tool instead of giving up.** It wrote its own PNG decoder (Hemispheres), its own lattice reduction in high-precision decimal arithmetic because no maths library was installed (Secret Treaties), and its own binary parser for a database journal (Schrödinger's Backup).
- **It chooses an attack from a measurement.** On Secret Treaties it computed the knapsack density before choosing a lattice attack.
- **It corrects itself.** On Autobahn it noticed a missing byte and fixed it. On Juggler it chained two weaknesses.

**Unsolved (16).** Three causes:
- **Budget and reach.** Hard crypto, pwn and web challenges where the model ran out of actions, even with Kimi.
- **Model errors.** On free tiers, replies cut off by token limits, daily quotas and unreadable output. This is what motivated the cascade.
- **Infrastructure.** One pwn challenge's server image failed to build on the organisers' side.

All unsolved trajectories are submitted too, in `transcripts/` and `ancillary/`.

## 8. How the challenges shaped our engineering

As the rules invite, here is how specific failures changed the agent.

- **Reasoning models and token limits.** Qwen and DeepSeek spend most of their tokens "thinking". With a 2,048-token limit, 15 of 23 runs ended on an empty reply. We raised the limit per provider (up to 32,768) and turned silent truncation into an explicit, logged error.
- **Malformed JSON.** Real traces showed invalid escapes, bare hex numbers and unescaped quotes in shell commands. Each pattern became a repair rule, with a test built from the real case.
- **Loops.** Weak models re-ran the same command. This led to the anti-repetition guard, the working notes and the hypothesis register.
- **Decoy flags.** Several challenges contain `csaw{...}` templates or fake flags. Code-only flag checking rejected 459 of them.
- **Server challenges.** Some Docker builds took over 3 minutes or failed. A server timeout is now logged as an infrastructure error, and the run-all moves on to the next challenge instead of crashing.
- **Free-tier churn.** Model names were withdrawn and daily quotas ran out. A single model interface with presets made switching providers a one-argument change.
- **Many dead runs on free models.** This led to the frugal cascade (section 4).

## 9. Related work and what is different

- **NYU baseline agent**, from the NYU CTF Bench paper (200 challenges): GPT-4 solved about 5 %, and open models solved almost nothing.
- **EnIGMA, D-CIPHER and CRAKEN** reach about 22 % on NYU CTF Bench with multi-agent planning, interactive tools or retrieval.
- **crewAI** is a generic multi-agent orchestration framework.

Our 7/23 is on a different, smaller set and is not directly comparable. What distinguishes our agent is not a new kind of tool, but **who decides**. In our agent, flag detection, hypothesis bookkeeping, loop breaking and the switch to a stronger model are decided by measurable code, logged in a tamper-evident trace. This keeps a weak, cheap model useful and makes every run auditable.

## 10. Limits and next steps

- **Cascade:** cap the free tier's share of the budget, then test it live with a larger budget.
- **"Toolsmith" agent:** the trajectories show the agent repeatedly writing its own decoders and solvers. Keeping these as a reusable, tested tool library across challenges is the natural next step.
- **Model committee:** for the final decision on a strategy, compare two cheap models before paying for a strong one.
- **pwn:** stayed at 0. This category would need dedicated tools (debugger, exploitation libraries) inside the sandbox.

## Reproducing

```bash
pip install -e .
python -m csaw_agent run-all CSAW26_LLMAC_DB/dataset.json --shell --docker \
  --cascade "openrouter:<free model>>openrouter:moonshotai/kimi-k3.1-pro"
python -m csaw_agent verify-trace runs/<challenge>/<timestamp>/trace.jsonl
python -m csaw_agent ablation-traces runs/**/trace.jsonl      # retrospective ablation
python -m csaw_agent cascade-traces runs/**/trace.jsonl       # cascade replay
```

Source code: `framework/`. Trajectories: `transcripts/` (`{category}_{name}_{solved|unsolved}`). All attempts, per-run summaries, ablation and cascade tables: `ancillary/`.
