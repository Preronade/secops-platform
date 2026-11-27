# Threat model (STRIDE)

Scope: the local platform in this repository. Out of scope: TLS, multi-user access and production hardening.

**Assets:** Telegram bot token, Jira API token, n8n credential store, the notes in the knowledge base, the integrity of triage decisions.

**Trust boundaries:** laptop localhost, the n8n webhook, the local LLM, and the external services (Telegram, Jira).

| # | Component | STRIDE | Threat | Current control | Status |
|---|---|---|---|---|---|
| 1 | n8n webhook | Spoofing | Anyone who can reach the webhook can submit forged findings and spam Jira and Telegram | Ports bound to 127.0.0.1; no webhook authentication | Partial |
| 2 | Triage prompt | Tampering | Untrusted finding text goes into the LLM prompt; a crafted finding could push it to rate itself LOW and suppress an alert | JSON-only prompt; parse fallback rates MEDIUM. Injection testing covered the RAG assistant, not this prompt | Open |
| 3 | Triage model | Tampering | A 3B model gives inconsistent output for the same alert | Routing uses severity only, not the action field | Partial |
| 4 | Telegram and Jira tokens | Information disclosure | Tokens leaked through the repo or exported workflow | Stored in n8n's credential store; `.env` is gitignored; n8n exports credential references, not values | Mitigated, manual check before pushing |
| 5 | Docker services | Information disclosure, elevation | Ollama and Chroma have no authentication; published on all interfaces they would be reachable from the LAN | Ports bound to 127.0.0.1 in `docker-compose.yml` | Mitigated |
| 6 | RAG assistant | Information disclosure | System-prompt secret extraction | Canary string in the prompt; output filter; no leak in the injection runs | Partial, substring matching only |
| 7 | RAG assistant | Tampering | Prompt injection changes behavior | Input regex plus output grounding check; 0 bypasses in the final sets | Partial, heuristic |
| 8 | Knowledge base | Tampering | A malicious note is ingested and its instructions appear in retrieved context | Notes come from local folders only; untested | Open |
| 9 | RAG assistant | Denial of service | Expensive or repeated requests | Question length 3 to 500 characters; localhost only; no authentication or rate limit | Partial |
| 10 | RAG assistant | Repudiation | No record of who asked what | None | Open |
| 11 | Scanners | Elevation, abuse | Scanning systems that are not yours | Refuse non-localhost unless `ALLOW_REMOTE=1`; GET requests only; response bodies not downloaded | Mitigated |
| 12 | Terraform sample | Tampering | The deliberately insecure file is applied by mistake | Scanned only, README warns against `terraform apply` | Mitigated by process |
| 13 | Adversarial-input detector | Tampering | An adaptive attacker who knows the detector can bypass 1-bit squeezing | Evaluated against non-adaptive attacks only; treated as an alarm, not a gate | Accepted, open |
| 14 | Separate model API | Spoofing, DoS | HS256 shared secret, no token revocation, per-IP in-memory rate limit | Documented in that project's README | Accepted, out of scope |
| 15 | Result files | Tampering | Result files edited after the fact | Git history only | Accepted |

## Next steps
1. Add Header Auth to the n8n webhook (closes #1).
2. Test the triage prompt for injection through finding text (closes #2).
3. Test indirect injection through ingested notes (closes #8).
4. Add authentication, rate limiting and request logging to `/ask` (closes #9 and #10).
