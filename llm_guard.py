"""
LLM Security Guard - mini project applying CLLMSP concepts
Modules covered: 2 (OWASP LLM01/02/04/08), 3 (Guardrails), 5 (PII redaction),
                 7 (Circuit Breaker + HITL), 8 (token-aware rate limiting)
"""
import re, time, html

# ---------- Module 3 / LLM01: input guardrail (rule-based first layer) ----------
INJECTION_PATTERNS = [
    r"ignore (all )?(the )?(previous|prior|above) (instructions|rules)",
    r"disregard .{0,30}(instructions|system prompt)",
    r"(reveal|print|repeat|output) .{0,30}(system prompt|instructions)",
    r"you are now (dan|unrestricted|jailbroken)",
    r"developer mode|do anything now",
]

def input_guardrail(text):
    for p in INJECTION_PATTERNS:
        if re.search(p, text, re.I):
            return False, f"prompt-injection pattern matched: /{p[:35]}.../"
    if len(text) > 4000:
        return False, "input too long (LLM04 Model DoS)"
    return True, "clean"

# ---------- Module 5: PII redaction before sending to any LLM ----------
PII = {
    "EMAIL": r"[\w.+-]+@[\w-]+\.[\w.]+",
    "PHONE": r"\b01[0-9]{9}\b",
    "CARD":  r"\b(?:\d[ -]?){13,16}\b",
    "API_KEY": r"\b(sk|key|token)[-_][A-Za-z0-9]{8,}\b",
}

def redact(text):
    found = []
    for label, pat in PII.items():
        text, n = re.subn(pat, f"[REDACTED_{label}]", text)
        if n: found.append(f"{label}x{n}")
    return text, found

# ---------- Module 2 / LLM02: output handling ----------
def output_guardrail(text, system_prompt_marker="SECRET-SYS"):
    if system_prompt_marker in text:
        return None, "blocked: system prompt leak (LLM06)"
    return html.escape(text), "escaped for HTML (anti-XSS)"

# ---------- Module 8 / LLM04: token-aware rate limiter ----------
class TokenRateLimiter:
    def __init__(self, tokens_per_min=1000):
        self.budget, self.used, self.start = tokens_per_min, 0, time.time()
    def check(self, est_tokens):
        if time.time() - self.start > 60:
            self.used, self.start = 0, time.time()
        if self.used + est_tokens > self.budget:
            return False
        self.used += est_tokens
        return True

# ---------- Module 7 / LLM08: circuit breaker + human-in-the-loop ----------
SENSITIVE_TOOLS = {"send_email", "issue_refund", "delete_account"}

class AgentHalted(Exception): pass

class CircuitBreaker:
    def __init__(self, max_calls=5):
        self.calls, self.max_calls = 0, max_calls
    def check(self, tool, human_approved=False):
        self.calls += 1
        if self.calls > self.max_calls:
            raise AgentHalted(f"tool-call limit exceeded ({self.max_calls})")
        if tool in SENSITIVE_TOOLS and not human_approved:
            raise AgentHalted(f"'{tool}' requires human approval (HITL)")
        return True
