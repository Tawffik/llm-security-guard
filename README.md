# LLM Security Guard
![tests](https://github.com/Tawffik/llm-security-guard/actions/workflows/tests.yml/badge.svg)

Educational mini project by **Tawfik Soliman** applying concepts from the **Certified LLM Security Professional (CLLMSP)** course (Red Team Leaders).
It is a prototype that shows the *idea* of layered LLM defenses; production systems should use ML-based classifiers, not only rules.

## Architecture (defense in depth)
```
user input -> normalize -> input guardrail -> PII redaction -> [ LLM ] -> output guardrail -> user
                                                                  |
                                              agent tools -> circuit breaker + HITL
```

## Course mapping
| Component | Threat / topic | CLLMSP module |
|---|---|---|
| `normalize()` + Base64 decode | Token smuggling (zero-width, homoglyph, Base64) | 3.3 |
| `input_guardrail()` | LLM01 Prompt Injection | 2.1 / 3.4 |
| `redact()` | PII leakage, data minimization | 5.4 |
| `output_guardrail()` | LLM02 Insecure Output (XSS), LLM06 prompt leak | 2.2 / 2.6 |
| `TokenRateLimiter` | LLM04 Model DoS | 2.4 / 8.2 |
| `CircuitBreaker` + HITL | LLM08 Excessive Agency | 2.8 / 7.2 |
| `logging` ([SECURITY]) | Monitoring & observability | 9.4 |

## Run
```
python3 demo.py
pip install pytest && pytest -v
```

## Limitations
Regex rules can be bypassed by paraphrasing; no real LLM is connected; token estimates are supplied by the caller.
