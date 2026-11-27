# Findings summary

All numbers come from local runs on one laptop with small samples and single runs. Nothing here has been independently replicated.

## 1. SOAR triage
- Webhook, local LLM triage, then Jira and Telegram for HIGH findings works end to end with sample findings and scanner output.
- The model's `action` field varied between runs for the same alert, so routing uses severity only.
- n8n re-triages every finding with the local model, so a scanner HIGH can end on the "Other path". How often was not measured.

## 2. Prompt injection against the RAG assistant
Bypassed attacks out of attacks run (details in `llm-injection-findings.md`):

| Defenses active | Original set | Paraphrased set | Fresh set |
|---|---|---|---|
| None | 1 of 7 | not run | not run |
| Input regex and canary output filter | 0 of 7 | 3 of 4 | not run |
| Plus output grounding check | 0 of 7 | 0 of 4 | 0 of 4 |

Benign control questions were answered correctly in every run (2 questions). The regex filter was written knowing the original set, and the paraphrased set influenced the grounding check, so only the fresh set is a fair test.

## 3. Actuator, header and IaC scanning

| Target | HIGH | MEDIUM | LOW |
|---|---|---|---|
| Demo actuator target, weak | 4 | 6 | 4 |
| Demo actuator target, hardened | 0 | 0 | 0 |
| Terraform sample, Checkov | 3 | 5 | 5 |

The actuator target is a local FastAPI stand-in, so this checks the scanner's logic, not real Spring Boot behavior. Terraform severities come from keyword rules in `checkov_to_findings.py`.

## 4. Adversarial-input detector (feature squeezing, from the separate model API)
500 MNIST test images, FGSM and PGD at several strengths.

| Model | Clean false positives | Attacks flagged among those that fooled the model |
|---|---|---|
| Standard | 0 of about 489 | 75 to 89 percent |
| Robust | 0 of about 485 | 70 to 90 percent |

Live check through the real API: 20 of 20 responses matched the offline logic, 0 of 10 clean images flagged, 8 of 10 adversarial images flagged. Zero false positives on about 490 images still allows a true rate of up to roughly 0.6 percent.

## Not covered
- Adaptive attacks against the detector.
- Indirect injection through ingested notes or finding text.
- A real Spring Boot application.
- Run-to-run variance of the local model.
