# target-angular — intentionally vulnerable Angular 19 payment UI

Seeded with one bug per rule in `orchestrator/rules/payments_angular/`.
**Do NOT use in production.** Used by the Agentic Security Platform to verify
each Angular rule fires against realistic patterns.

| File | Seeded vulnerabilities |
|---|---|
| `src/app/services/auth.service.ts`     | Token in localStorage |
| `src/app/services/payment.service.ts`  | Card data in storage, client-amount POSTed |
| `src/app/components/admin.component.ts` | bypassSecurityTrustHtml, console.log of PAN, innerHTML assignment |
