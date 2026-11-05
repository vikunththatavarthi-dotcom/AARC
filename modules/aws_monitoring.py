"""Read-only AWS resource monitoring for AARC."""
import json

import boto3


def get_ec2_instances(region="ap-south-1"):
    """Return real EC2 instance information from AWS."""
    client = boto3.client("ec2", region_name=region)
    response = client.describe_instances()

    instances = []
    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            name = next(
                (
                    tag["Value"]
                    for tag in instance.get("Tags", [])
                    if tag["Key"] == "Name"
                ),
                "(unnamed)",
            )
            instances.append({
                "instance_id": instance["InstanceId"],
                "name": name,
                "state": instance.get("State", {}).get("Name", "unknown"),
                "instance_type": instance.get("InstanceType"),
                "availability_zone": instance.get("Placement", {}).get(
                    "AvailabilityZone"
                ),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
            })

    return instances


def get_cloudtrail_events(region="ap-south-1", max_results=50):
    """Return recent CloudTrail management events with context.

    Uses pagination but caps the total number of events returned.
    This function only reads CloudTrail data.
    """
    client = boto3.client("cloudtrail", region_name=region)
    events = []
    seen_ids = set()
    next_token = None

    while len(events) < max_results:
        page_size = min(50, max_results - len(events))
        params = {"MaxResults": page_size}

        if next_token:
            params["NextToken"] = next_token

        response = client.lookup_events(**params)

        for event in response.get("Events", []):
            event_id = event.get("EventId")

            if event_id and event_id in seen_ids:
                continue

            if event_id:
                seen_ids.add(event_id)

            raw = {}
            raw_text = event.get("CloudTrailEvent")

            if raw_text:
                try:
                    raw = json.loads(raw_text)
                except (TypeError, json.JSONDecodeError):
                    raw = {}

            identity = raw.get("userIdentity") or {}
            session_context = (
                identity.get("sessionContext") or {}
            ).get("sessionIssuer") or {}

            username = (
                event.get("Username")
                or identity.get("userName")
                or session_context.get("userName")
                or identity.get("principalId")
                or "Unknown"
            )

            events.append({
                "event_id": event_id,
                "time": (
                    event["EventTime"].isoformat()
                    if event.get("EventTime")
                    else None
                ),
                "event_name": event.get("EventName", "Unknown"),
                "event_source": event.get("EventSource", "Unknown"),
                "username": username,
                "region": raw.get("awsRegion", region),
                "source_ip": raw.get("sourceIPAddress"),
                "user_agent": raw.get("userAgent"),
                "error_code": raw.get("errorCode"),
                "error_message": raw.get("errorMessage"),
                "read_only": raw.get("readOnly"),
                "identity_type": identity.get("type"),
            })

            if len(events) >= max_results:
                break

        next_token = response.get("NextToken")
        if not next_token:
            break

    return events
