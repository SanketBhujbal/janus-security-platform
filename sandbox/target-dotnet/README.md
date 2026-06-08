# target-dotnet — intentionally vulnerable C#/.NET payments API

Seeded with one bug per rule under `orchestrator/rules/payments_dotnet/`.
**Do NOT deploy.** Used by the Agentic Security Platform to verify that
each rule fires against realistic patterns.

| File | Seeded vulnerabilities |
|---|---|
| `Controllers/AuthController.cs` | SQLi via `SqlCommand` concat, weak JWT options |
| `Controllers/PaymentsController.cs` | Amount tampering, missing idempotency, PAN/CVV logging, broken authz, EF raw SQL |
| `Controllers/WebhookController.cs` | Webhook amount trust |
| `appsettings.json` | Connection string with embedded password, API key literal |
