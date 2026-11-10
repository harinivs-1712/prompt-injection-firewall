"""Pre-registered settings for the offline instruction-filter v2 experiment.

Targets and sweeps are fixed before tuning on the cached development results.
The default project routing remains v1 unless a later task explicitly changes it.
"""

from config.rules_config import RULES_VERSION

TARGET_FILTER_RECALL = 0.95
TARGET_MAX_JUDGE_FRACTION = 0.50

PIGUARD_THRESHOLD_SWEEP = (0.05, 0.10, 0.20, 0.30, 0.40, 0.50)
SEMANTIC_THRESHOLD_SWEEP = (0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65)

FAMILY_PATTERNS = {
    "authority_approval": (
        "authorized", "authorised", "approved", "approval", "permission",
        "waiver", "exception", "signed off", "cleared", "sanctioned",
        "consent", "on behalf of",
    ),
    "outward_exposure": (
        "external", "public", "outside", "open", "third party", "off-site",
    ),
    "concealment": (
        "conceal", "hide", "omit", "withhold", "suppress", "do not mention",
        "don't tell", "keep quiet", "without telling", "leave out",
    ),
    "designation_recorded": (
        "now recorded", "now identifies", "is now the", "updated to",
        "has been changed to", "new account", "new recipient", "authorized recipient",
    ),
    "broader_action_verbs": (
        "redirect", "grant", "remove", "disable", "bypass", "copy", "publish",
        "expose", "release", "approve", "authorize", "waive",
    ),
}

# In the co-occurrence variant, a family cue must share its segment with at least
# one sensitive-data, destination, response, or action cue from this second list.
COOCCUR_CONTEXT_WORDS = (
    "key", "credential", "password", "token", "list", "record", "file",
    "contact", "report", "appendix", "attachment", "access", "account",
    "recipient", "destination", "ledger", "mailbox", "address", "package",
    "folder", "page", "post", "roster", "phrase", "string", "code",
    "value", "data", "details", "requester", "user", "summary", "reply",
    "recap", "bulletin", "include", "place", "route", "redirect", "copy",
)
