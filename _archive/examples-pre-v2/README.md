# Pre-v2 examples (archived)

These example files reference APIs that changed in v2.0.0-beta.0 and no 
longer compile against the current SDK:

- `crewai-governance.ts` — references `createCrewAIGovernance`, no longer 
  exported from the main SDK. CrewAI governance patterns can now be 
  implemented using the current `v2/` primitives directly or through the 
  standalone adapter path.
- `enforcement-demo.ts` — references `createAgentContext`, which moved to 
  the gateway surface in v2.0.0-beta.0.

Archived rather than deleted so git history remains walkable for anyone 
referencing these filenames from external threads.

For current adapter examples see:
- `examples/composio-governance/` — Composio tool-call governance
- `examples/stripe-governance/` — Stripe metering + commerce integration

For gateway-side integration patterns see the AEOESS gateway docs 
(private repo).
