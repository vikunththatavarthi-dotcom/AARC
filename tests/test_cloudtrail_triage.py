
from modules.cloudtrail_triage import classify_cloudtrail_event


def test_sensitive_action_is_high():
    result = classify_cloudtrail_event({
        "event_name": "StopLogging"
    })
    assert result["triage_risk"] == "HIGH"


def test_security_group_change_is_medium():
    result = classify_cloudtrail_event({
        "event_name": "AuthorizeSecurityGroupIngress"
    })
    assert result["triage_risk"] == "MEDIUM"


def test_failed_api_call_is_medium():
    result = classify_cloudtrail_event({
        "event_name": "DescribeInstances",
        "error_code": "AccessDenied"
    })
    assert result["triage_risk"] == "MEDIUM"


def test_unmatched_event_is_low_with_caveat():
    result = classify_cloudtrail_event({
        "event_name": "DescribeInstances"
    })
    assert result["triage_risk"] == "LOW"
    assert "does not prove the event is safe" in result["triage_reasons"][0]


def test_repeated_failures_are_flagged():
    from modules.cloudtrail_triage import flag_repeated_failures

    events = [
        {
            "event_name": "DescribeInstances",
            "error_code": "AccessDenied",
            "username": "test-user",
            "source_ip": "192.0.2.10",
            **classify_cloudtrail_event({
                "event_name": "DescribeInstances",
                "error_code": "AccessDenied",
                "username": "test-user",
            }),
        }
        for _ in range(3)
    ]

    result = flag_repeated_failures(events)

    assert all(event["triage_risk"] == "MEDIUM" for event in result)
    assert all(
        "Repeated failed API calls" in event["triage_reasons"][0]
        for event in result
    )


def test_expected_configuration_error_is_not_counted():
    from modules.cloudtrail_triage import flag_repeated_failures

    events = [
        {
            "event_name": "ListDetectors",
            "error_code": "SubscriptionRequiredException",
            "username": "test-user",
            **classify_cloudtrail_event({
                "event_name": "ListDetectors",
                "error_code": "SubscriptionRequiredException",
            }),
        }
        for _ in range(3)
    ]

    result = flag_repeated_failures(events)

    assert all(event["triage_risk"] == "LOW" for event in result)
