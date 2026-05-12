from __future__ import annotations

from ..models import Evidence, Finding, ScanContext
from ..schema import dangerous_mutations, sensitive_fields, unbounded_list_queries


def check_introspection_exposed(ctx: ScanContext, schema: dict | None) -> list[Finding]:
    if not schema:
        return [
            Finding(
                rule_id="GPL-RECON-001",
                title="Introspection unavailable",
                severity="low",
                confidence="medium",
                description="Introspection appears disabled or blocked; fallback recon should be used.",
                owasp="API9: Improper Inventory Management",
                tags=["recon", "introspection"],
            )
        ]
    return [
        Finding(
            rule_id="GPL-RECON-002",
            title="Introspection enabled",
            severity="medium",
            confidence="high",
            description="GraphQL introspection is enabled and may expose attack surface details to attackers.",
            cwe="CWE-200",
            owasp="API8: Security Misconfiguration",
            tags=["recon", "introspection", "exposure"],
        )
    ]


def check_dangerous_mutations(ctx: ScanContext, schema: dict | None) -> list[Finding]:
    if not schema:
        return []
    muts = dangerous_mutations(schema)
    if not muts:
        return []
    preview = ", ".join(muts[:10])
    return [
        Finding(
            rule_id="GPL-AUTHZ-001",
            title="Potentially dangerous mutations discovered",
            severity="high",
            confidence="medium",
            description=f"Destructive or high-impact mutation names were detected: {preview}",
            owasp="API5: Broken Function Level Authorization",
            tags=["authz", "mutation", "business-logic"],
            evidence=[Evidence(note=f"Detected mutations: {preview}")],
        )
    ]


def check_sensitive_fields(ctx: ScanContext, schema: dict | None) -> list[Finding]:
    if not schema:
        return []
    risky = sensitive_fields(schema)
    if not risky:
        return []
    count = sum(len(v) for v in risky.values())
    sample_type = next(iter(risky.keys()))
    sample_fields = ", ".join(risky[sample_type][:5])
    return [
        Finding(
            rule_id="GPL-EXPO-001",
            title="Potential sensitive fields in schema",
            severity="medium",
            confidence="low",
            description=(
                f"Detected {count} potentially sensitive fields by name heuristic. "
                f"Example: {sample_type}.{sample_fields}"
            ),
            cwe="CWE-200",
            owasp="API3: Broken Object Property Level Authorization",
            tags=["data-exposure", "schema"],
        )
    ]


def check_unbounded_list_queries(ctx: ScanContext, schema: dict | None) -> list[Finding]:
    if not schema:
        return []
    risky = unbounded_list_queries(schema)
    if not risky:
        return []
    return [
        Finding(
            rule_id="GPL-DOS-001",
            title="Potential unbounded list query exposure",
            severity="medium",
            confidence="medium",
            description=(
                "List-returning queries without common pagination arguments were found, "
                "which can increase DoS risk."
            ),
            owasp="API4: Unrestricted Resource Consumption",
            tags=["dos", "pagination", "availability"],
            evidence=[Evidence(note=f"Queries: {', '.join(risky[:10])}")],
        )
    ]


BUILTIN_CHECKS = [
    check_introspection_exposed,
    check_dangerous_mutations,
    check_sensitive_fields,
    check_unbounded_list_queries,
]
