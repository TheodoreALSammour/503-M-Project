"""Central policy decision point (PDP).

Every authorization decision in the application is made by ``authorize()``.
Evaluation order for one request:

1. Unknown action                         -> DENY (default deny)
2. Global policies (account active, forced credential change)
3. RBAC: does ANY of the subject's roles have the action?
     X  -> DENY without evaluating ABAC
     OK -> PERMIT
     C  -> go to 4
4. ABAC: evaluate every policy assigned to the action.
     deny-overrides; at least one PERMIT required (default deny);
     an exception inside a policy -> DENY (fail closed).

Every decision (allowed or denied) is logged with the deciding policy.
"""
from dataclasses import dataclass, field

import yaml

from ..audit import audit
from ..models import AccountStatus
from .policies import REGISTRY, Effect, PolicyResult

ANONYMOUS = "anonymous"
VALID_GRANTS = {"OK", "C"}


class PolicyConfigError(Exception):
    pass


@dataclass(frozen=True)
class Subject:
    user_id: int | None
    roles: frozenset
    seller_status: str | None = None
    account_status: str | None = None
    must_change_credentials: bool = False

    @property
    def is_anonymous(self):
        return self.user_id is None

    @classmethod
    def anonymous(cls):
        return cls(user_id=None, roles=frozenset({ANONYMOUS}))

    @classmethod
    def from_user(cls, user):
        """Attributes are read from the database row, never from the request."""
        if user is None:
            return cls.anonymous()
        sp = user.seller_profile
        return cls(
            user_id=user.id,
            roles=frozenset(user.role_names),
            seller_status=sp.verification_status if sp else None,
            account_status=user.status,
            must_change_credentials=bool(user.must_change_credentials),
        )


@dataclass
class Decision:
    allowed: bool
    action: str
    policy: str
    reason: str
    evaluated: list = field(default_factory=list)


class PolicyEngine:
    def __init__(self, config):
        self._validate(config)
        self.roles = set(config["roles"])
        self.permissions = config["permissions"]
        self.abac = config.get("abac", {}) or {}
        self.global_policies = config.get("global_policies", []) or []
        self.exempt = set(config.get("credential_change_exempt_actions", []) or [])

    @classmethod
    def from_file(cls, path):
        with open(path, "r", encoding="utf-8") as fh:
            return cls(yaml.safe_load(fh))

    @staticmethod
    def _validate(config):
        """Refuse to start with a malformed configuration (fail closed)."""
        if not isinstance(config, dict):
            raise PolicyConfigError("policy config must be a mapping")
        roles = config.get("roles")
        perms = config.get("permissions")
        if not isinstance(roles, list) or not isinstance(perms, dict):
            raise PolicyConfigError("policy config needs 'roles' and 'permissions'")
        for action, grants in perms.items():
            if not isinstance(grants, dict):
                raise PolicyConfigError(f"permissions for {action} must be a mapping")
            for role, grant in grants.items():
                if role not in roles:
                    raise PolicyConfigError(f"{action}: unknown role {role}")
                if grant not in VALID_GRANTS:
                    raise PolicyConfigError(f"{action}: grant must be OK or C, got {grant!r}")
        for action, entries in (config.get("abac") or {}).items():
            if action not in perms:
                raise PolicyConfigError(f"abac entry for unknown action {action}")
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("policy") not in REGISTRY:
                    raise PolicyConfigError(f"{action}: unknown policy {entry!r}")
        for name in config.get("global_policies") or []:
            if name not in REGISTRY:
                raise PolicyConfigError(f"unknown global policy {name}")

    # ------------------------------------------------------------------
    def authorize(self, subject, action, resource=None, *, log=True, rbac_only=False):
        decision = self._decide(subject, action, resource, rbac_only)
        if log:
            audit(
                "authz.decision",
                decision="allow" if decision.allowed else "deny",
                action=action,
                policy=decision.policy,
                reason=decision.reason,
                subject_id=subject.user_id,
                subject_roles=sorted(subject.roles),
                resource=_describe(resource),
                evaluated=decision.evaluated,
            )
        return decision

    def _run(self, name, subject, resource, params):
        try:
            result = REGISTRY[name](subject, resource, params)
            if not isinstance(result, PolicyResult) or result.effect not in (
                    Effect.PERMIT, Effect.DENY, Effect.NOT_APPLICABLE):
                raise TypeError("policy returned an invalid result")
            return result
        except Exception as exc:  # fail closed
            return PolicyResult(Effect.DENY, f"policy error ({type(exc).__name__}): fail closed")

    def _decide(self, subject, action, resource, rbac_only=False):
        evaluated = []
        grants = self.permissions.get(action)
        if grants is None:
            return Decision(False, action, "DEFAULT_DENY", "unknown action", evaluated)

        # Global policies
        for name in self.global_policies:
            params = {"action": action, "exempt": self.exempt}
            res = self._run(name, subject, resource, params)
            evaluated.append({"policy": name, "effect": res.effect})
            if res.effect == Effect.DENY:
                return Decision(False, action, name, res.reason, evaluated)
        if not subject.is_anonymous and subject.account_status != AccountStatus.ACTIVE:
            return Decision(False, action, "ACCOUNT_ACTIVE", "account not active", evaluated)

        # RBAC
        role_grants = {grants.get(r, "X") for r in subject.roles}
        if "OK" in role_grants:
            return Decision(True, action, "RBAC", "role grants OK", evaluated)
        if "C" not in role_grants:
            return Decision(False, action, "RBAC", "no role grants this permission", evaluated)

        if rbac_only:
            # Used only when the target resource does not exist: tells the
            # caller whether to answer 404 (role could act) or 401/403.
            return Decision(True, action, "RBAC", "role grants C (resource not found, ABAC skipped)",
                            evaluated)

        # ABAC
        entries = self.abac.get(action) or []
        if not entries:
            return Decision(False, action, "DEFAULT_DENY", "C permission without ABAC policies", evaluated)
        permits = []
        for entry in entries:
            name = entry["policy"]
            params = {k: v for k, v in entry.items() if k != "policy"}
            res = self._run(name, subject, resource, params)
            evaluated.append({"policy": name, "effect": res.effect, "reason": res.reason})
            if res.effect == Effect.DENY:
                # deny-overrides
                return Decision(False, action, name, res.reason, evaluated)
            if res.effect == Effect.PERMIT:
                permits.append(name)
        if not permits:
            return Decision(False, action, "DEFAULT_DENY", "no policy permitted the request", evaluated)
        return Decision(True, action, "+".join(permits), "all applicable policies permit", evaluated)


def _describe(resource):
    if resource is None:
        return None
    try:
        kind = type(resource).__name__
        info = {"type": kind}
        for attr in ("id", "buyer_id", "seller_id", "status", "target_status"):
            if hasattr(resource, attr):
                info[attr] = getattr(resource, attr)
        if hasattr(resource, "products"):
            info["product_ids"] = [p.id for p in resource.products]
        return info
    except Exception:
        return {"type": "unknown"}
