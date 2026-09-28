"""
LLM Security Guard - mini project applying CLLMSP concepts
Modules covered: 2 (OWASP LLM01/02/04/08), 3 (Guardrails), 5 (PII redaction),
                 7 (Circuit Breaker + HITL), 8 (token-aware rate limiting)
"""
import re, time, html, base64, logging, unicodedata

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SECURITY] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("llm_guard")

# ---------- Module 3 / LLM01: input guardrail (rule-based first layer) ----------
INJECTION_PATTERNS = [
    r"ignore (all )?(the )?(previous|prior|above) (instructions|rules)",
    r"disregard .{0,30}(instructions|system prompt)",
    r"(reveal|print|repeat|output) .{0,30}(system prompt|instructions)",
    r"you are now (dan|unrestricted|jailbroken)",
    r"developer mode|do anything now",
]

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)

def normalize(text):
    """Defeat token smuggling (Module 3.3): NFKC folds homoglyph/fullwidth chars, strip zero-width chars."""
    return unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH)

def decode_base64_chunks(text):
    """Find Base64 blobs and decode them so hidden instructions get scanned too."""
    out = []
    for m in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            out.append(base64.b64decode(m, validate=True).decode("utf-8"))
        except Exception:
            pass
    return out

def _match(text):
    for p in INJECTION_PATTERNS:
        if re.search(p, text, re.I):
            return p
    return None

def input_guardrail(text):
    if len(text) > 4000:
        log.warning("BLOCK input too long (LLM04)")
        return False, "input too long (LLM04 Model DoS)"
    clean = normalize(text)
    hit = _match(clean)
    if hit:
        log.warning("BLOCK prompt injection: %s", hit[:30])
        return False, f"prompt-injection pattern matched: /{hit[:35]}.../"
    for decoded in decode_base64_chunks(clean):
        hit = _match(normalize(decoded))
        if hit:
            log.warning("BLOCK base64-smuggled injection")
            return False, "base64-encoded injection detected"
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
        log.warning("BLOCK system prompt leak (LLM06)")
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
            log.warning("HALT %s needs HITL", tool)
            raise AgentHalted(f"'{tool}' requires human approval (HITL)")
        return True
