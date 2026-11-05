"""Read-only, explainable rule-based triage for AWS CloudTrail events."""

HIGH_RISK_ACTIONS = {
    "StopLogging",
    "DeleteTrail",
    "PutEventSelectors",
    "CreateAccessKey",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
}

MEDIUM_RISK_ACTIONS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "UpdateTrail",
    "DeleteUser",
    "DeleteRole",
}

# These failures can occur because a service is not enabled or subscribed.
# They should not, by themselves, be treated as evidence of an attack.
EXPECTED_CONFIGURATION_ERRORS = {
    "SubscriptionRequiredException",
}

# These actions are common read-only API operations. They are not
# automatically safe, but they do not warrant an alert by themselves.
ROUTINE_READ_ACTIONS = {
    "DescribeInstances",
    "DescribeRegions",
    "DescribeSecurityGroups",
    "DescribeVpcs",
    "ListBuckets",
    "ListUsers",
    "ListRoles",
    "ListPolicies",
    "LookupEvents",
    "GetCallerIdentity",
    "ListDetectors",
}


def classify_cloudtrail_event(event):
    """Classify one event without making AWS changes."""
    event_name = event.get("event_name") or "Unknown"
    error_code = event.get("error_code")
    identity_type = event.get("identity_type") or "Unknown"
    username = event.get("username") or "Unknown"

    context = f"Identity type: {identity_type}; principal: {username}."

    # Sensitive actions take priority, even if the event has other context.
    if event_name in HIGH_RISK_ACTIONS:
        return {
            "triage_risk": "HIGH",
            "triage_reasons": [
                f"Sensitive AWS action detected: {event_name}.",
                context,
                "Review the principal, timestamp, and surrounding activity.",
            ],
        }

    if event_name in MEDIUM_RISK_ACTIONS:
        return {
            "triage_risk": "MEDIUM",
            "triage_reasons": [
                f"Security-sensitive AWS action detected: {event_name}.",
                context,
                "Verify that this change was expected and authorized.",
            ],
        }

    if error_code in EXPECTED_CONFIGURATION_ERRORS:
        return {
            "triage_risk": "LOW",
            "triage_reasons": [
                f"AWS service configuration or subscription issue: {error_code}.",
                "This error alone is not evidence of malicious activity.",
                context,
            ],
        }

    if error_code:
        return {
            "triage_risk": "MEDIUM",
            "triage_reasons": [
                f"AWS API call failed with error code: {error_code}.",
                "A failed call requires context; it does not prove an attack.",
                context,
            ],
        }

    if event_name in ROUTINE_READ_ACTIONS:
        return {
            "triage_risk": "LOW",
            "triage_reasons": [
                "No configured sensitive-action rule matched; this does not prove the event is safe.",
                f"Recognized routine read/list operation: {event_name}.",
                "Review frequency and surrounding events if the activity is unexpected.",
                context,
            ],
        }

    return {
        "triage_risk": "LOW",
        "triage_reasons": [
            f"No configured sensitive-action rule matched: {event_name}.",
            "This does not prove the event is safe.",
            context,
        ],
    }


def flag_repeated_failures(events, threshold=3):
    """Flag repeated failed API calls from the same identity in one batch."""
    from collections import Counter

    def identity_key(event):
        username = event.get("username")
        source_ip = event.get("source_ip")

        if username and username != "Unknown":
            return f"user:{username}"
        if source_ip:
            return f"ip:{source_ip}"
        return None

    failure_counts = Counter(
        identity_key(event)
        for event in events
        if event.get("error_code")
        and event.get("error_code") not in EXPECTED_CONFIGURATION_ERRORS
        and identity_key(event) is not None
    )

    for event in events:
        key = identity_key(event)
        if (
            key
            and event.get("error_code")
            and event.get("error_code") not in EXPECTED_CONFIGURATION_ERRORS
            and failure_counts[key] >= threshold
        ):
            event["triage_risk"] = "MEDIUM"
            reasons = event.setdefault("triage_reasons", [])
            message = (
                f"Repeated failed API calls: {failure_counts[key]} "
                f"failures for the same identity in this event batch."
            )
            if message not in reasons:
                reasons.insert(0, message)

    return events
