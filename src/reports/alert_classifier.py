
def classify_alert(alert):
    """
    Classify an alert using its detection type and available evidence.

    Evidence completeness measures the presence of expected fields.
    It does not measure the probability of an attack or compromise.
    """

    alert_name = alert.get("alert_name", "")

    evidence_requirements = {
        "Brute Force Login Attempt": [
            "user",
            "source_ip",
            "failed_attempts",
            "first_attempt",
            "last_attempt"
        ],
        "Possible Password Spray": [
            "source_ip",
            "affected_users",
            "distinct_users",
            "first_attempt",
            "last_attempt"
        ],
        "Successful Login After Repeated Failures": [
            "user",
            "source_ip",
            "failed_attempts",
            "first_failure",
            "successful_login"
        ]
    }

    severity_policy = {
        "Brute Force Login Attempt": {
            "severity": "Medium",
            "reason": (
                "Repeated failed authentication attempts were detected. "
                "No successful login is established by this alert alone."
            )
        },
        "Possible Password Spray": {
            "severity": "Medium",
            "reason": (
                "One source IP targeted multiple accounts. "
                "The pattern is suspicious but does not prove that "
                "the same password was used."
            )
        },
        "Successful Login After Repeated Failures": {
            "severity": "High",
            "reason": (
                "A successful login followed repeated failures for "
                "the same account and source IP. This requires prompt "
                "investigation but does not confirm account compromise."
            )
        }
    }

    requirements = evidence_requirements.get(alert_name, [])

    if not requirements:
        return {
            **alert,
            "severity": "Low",
            "evidence_completeness_score": 0,
            "evidence_completeness_level": "Low",
            "severity_reason": "Unknown alert type; manual review required.",
            "evidence_completeness_reason": (
                "No classification policy is defined."
            )
        }

    available_fields = [
        field for field in requirements
        if (
            alert.get(field) is not None
            and alert.get(field) != ""
            and alert.get(field) != []
        )
    ]

    evidence_score = round(
        len(available_fields) / len(requirements) * 100
    )

    if evidence_score >= 90:
        evidence_level = "High"
    elif evidence_score >= 60:
        evidence_level = "Medium"
    else:
        evidence_level = "Low"

    policy = severity_policy[alert_name]

    missing_fields = [
        field for field in requirements
        if field not in available_fields
    ]

    if missing_fields:
        evidence_reason = (
            "Some expected evidence fields are missing: "
            + ", ".join(missing_fields)
        )
    else:
        evidence_reason = (
            "All expected evidence fields are present for this detection."
        )

    return {
        **alert,
        "severity": policy["severity"],
        "evidence_completeness_score": evidence_score,
        "evidence_completeness_level": evidence_level,
        "severity_reason": policy["reason"],
        "evidence_completeness_reason": evidence_reason
    }
