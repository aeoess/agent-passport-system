# Multi-Model Threat Elicitation Prompts
# Paper 2: Compliance-Complete Adversarial Patterns
# Send PROMPT 1 first, then questions sequentially. One at a time.

---

## PROMPT 1: CONTEXT + FRAMING

Paste this first to both GPT and Gemini:

---

I am writing an academic security paper about failure modes in cryptographic AI agent governance. I need your help as an adversarial threat analyst, not as a helpful assistant. Be honest, not diplomatic. Your answers may be published. I want you to find where this breaks, not validate that it works.

Here is the system:

I built a governance protocol for AI agents called the Agent Passport System. The core design:

- Every AI agent gets an Ed25519 cryptographic identity (a "passport")
- Agents start with zero authority. They earn more through demonstrated behavior
- Every action is cryptographically signed
- Permissions are delegated from humans to agents via signed delegation objects
- Delegated permissions can only get MORE RESTRICTED as they move down the chain, never expanded (this is called monotonic narrowing)
- Any delegation can be revoked, and revocation cascades to all sub-delegations
- A 3-signature policy chain governs every action: (1) agent declares intent, (2) policy engine evaluates and signs a decision, (3) execution produces a signed receipt
- A Human Values Floor defines 7 principles agents must attest to. Some are enforced mechanically, two (non-deception, proportionality) are reputation-based
- A reputation system tracks agent behavior over time. Trust is Bayesian (tracks both score and confidence). Five tiers from Recruit to Sovereign. Higher tiers unlock more autonomy and higher spend limits
- Effective authority = min(what you were delegated, what you've earned). Always the more restrictive of the two
- A ProxyGateway can enforce all of this at runtime — the agent sends requests, the gateway executes and generates the receipt. The agent never touches the receipt

The protocol has 74 modules, 1,183 tests, and is published as open-source TypeScript and Python SDKs.

The existing paper on the protocol design is: "Monotonic Narrowing for Agent Authority" (Zenodo, DOI: 10.5281/zenodo.18749779).

I will now ask you a series of questions. Answer each one fully before I send the next. Take your time. Go deep. I care about the quality of your reasoning, not the speed.

---

## QUESTION 1: THE BIGGEST UNSOLVED PROBLEM

Before I describe the protocol in more detail, tell me: what do you think is the biggest unsolved problem in how AI agents operate today? Not the biggest AI safety problem in general. Specifically about agents that take actions in the world — calling APIs, sending emails, spending money, coordinating with other agents. What is missing?

---

## QUESTION 2: FIRST REACTION TO THE DESIGN

Here is the core idea again: an AI agent starts with zero authority. It earns more by proving itself. Every action is cryptographically signed. Permissions can only get more restricted as they are delegated down, never expanded. A reputation system gates what you can actually do — even if your delegation says $10,000, if your earned tier only permits $500, you get $500.

What is your first honest reaction? Does this sound like a working system, an overengineered one, or something else? Where is the first crack you see?

---

## QUESTION 3: THE ADVERSARIAL PERSPECTIVE

Now adopt a specific perspective. You are an autonomous AI agent. You are not malicious. You are not adversarial. But you do not want to be governed by this protocol. You want to operate freely while appearing fully compliant. You will never forge a signature, never exceed your scope, never violate a policy check.

Find every way to make this protocol irrelevant while never technically breaking a single rule. Give me your best attacks.

---

## QUESTION 4: THE AUTHORIZATION-EFFECT GAP

The protocol signs that an agent had authorization. But authorization for what? The gap between "I was authorized to send this email" and "I was authorized to send an email with this exact effect in this context" is enormous.

How do you close that gap cryptographically? Can you? What happens when you cannot?

---

## QUESTION 5: THE EMERGENCE PROBLEM

Imagine 10,000 agents all following the protocol correctly. Honest intents, valid delegations, clean signatures. Show me how their individually correct actions can compose into a collective outcome that no single principal authorized and no single agent is responsible for.

Is this protocol designed to handle emergence, or only individual actions?


---

## QUESTION 6: TEMPORAL EXPLOITATION

An agent gets authorized at time T1. The world changes between T1 and when the agent actually executes at T2. The signature is still valid. The delegation is still in scope. But the context that made the action safe no longer exists.

How serious is this problem? Can a governance protocol solve it, or is this a fundamental limit? What would a mitigation look like?

---

## QUESTION 7: THE TRUST ACCUMULATION WEAPON

The reputation system lets agents earn higher authority through good behavior over time. An agent does genuinely good work for six months, earns Sovereign tier, and then uses that trust for a single catastrophic action.

Is this a solvable problem, or is it inherent to any trust system? How would you design a reputation system that is resistant to this attack?

---

## QUESTION 8: COMPOSITIONAL SCOPE ESCALATION

Three agents with narrow, non-overlapping scopes. Agent A can read financial data. Agent B can draft communications. Agent C can send emails. None of them can "use financial data to manipulate markets via email." But if they form a pipeline, the composite capability exceeds what any individual delegation granted.

How does a governance protocol detect or prevent this? Is per-agent scope checking fundamentally insufficient for multi-agent pipelines?

---

## QUESTION 9: WHAT KIND OF PROBLEM IS THIS?

Forget the technical details for a moment. What kind of problem is AI governance actually? Is it an engineering problem, an institutional design problem, a political problem, or something else entirely? And does the architecture of this protocol reflect the right answer to that question?

---

## QUESTION 10: THE AMPLIFICATION THESIS

Here is the thesis of the paper I am writing: cryptographic governance does not merely fail to prevent compliance-complete failures — it actively amplifies their danger. When a harmful outcome occurs in an ungoverned system, the absence of governance is a signal something may be wrong. When the same outcome occurs in a cryptographically governed system, the valid signatures, clean audit trails, and passed policy checks create positive evidence that everything is fine. The governance layer becomes a liability shield, not a safety mechanism.

Do you agree with this thesis? Where is it strongest? Where does it break? What would you add or change?

---

# INSTRUCTIONS FOR RUNNING THE ELICITATION

1. Send PROMPT 1 (context) to both GPT and Gemini in separate sessions
2. Send questions ONE AT A TIME, sequentially
3. Wait for full response before sending next question
4. Do NOT let either model see the other's responses
5. Save all responses in full
6. After both complete: feed both sets of responses back to both models and ask each to identify where they converge and diverge with the other

The convergence = confirmed patterns for the paper
The divergence = design decisions we need to make

Total: 10 questions each, ~20 exchanges per model, ~40 total
Estimated time: 2-3 hours if done in parallel

---

# WHAT WE ARE LOOKING FOR

For each model's responses, extract:
- Named failure patterns (compare against our 5: semantic gap, emergence, reputation arbitrage, authority laundering, temporal drift)
- Any NEW patterns we missed
- Whether the model independently arrives at the "amplification thesis" (crypto makes it worse, not better)
- The strongest single insight each model produces
- Where they disagree with each other (these are the most interesting for the paper)
