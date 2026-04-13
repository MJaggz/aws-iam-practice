# ============================================================
# PROJECT  : aws-security-toolkit
# FILE     : problems/problem_07_trust_policy.py
# PROBLEM  : Trust Policy Validator — "Who Can Assume This Role?"
# ============================================================
# Difficulty  : Medium-Hard
# Topic       : IAM Trust Policies, Principal Classification,
#               Cross-Account Security, Condition Blocks
# Style       : AWS Interview / Internship Simulation
# Concepts    : sts:AssumeRole, ExternalId, Confused Deputy,
#               Principal normalization, Policy scanning,
#               Action metadata registry
# ============================================================
#
# BACKGROUND
# ----------
# Every IAM role has a trust policy that controls WHO can assume it.
# You are building a validator for an internal cloud governance tool
# that scans trust policies before roles are deployed to production.
#
# Your validator will be used as the logic core of a GuardHook —
# a pre-deployment check that blocks CloudFormation stacks if a
# role's trust policy has critical or high-severity issues.
#
# This file also includes an  action metadata registry.
# In real AWS tooling (like IAM Access Analyzer or internal policy
# scanners), validators are backed by a metadata registry that
# describes what every action does — whether it reads, writes,
# manages permissions, or only tags resources.
#
# In later problems, you will use this registry to cross-reference
# actions in a policy against their risk classification.
#
# CALLER CONTEXT
# --------------
# Assume the deploying account ID is: "123456789012"
# This is used to distinguish same-account vs cross-account principals.
#
# ============================================================


import json


# ============================================================
# METADATA REGISTRY
# ============================================================
# This section provides a reference table of EC2 actions and
# their security-relevant properties. You do not need to modify
# this section. Use the helper functions below it to query it.
#
# Properties explained:
#   IsList               — action returns a list of resources (read-like)
#   IsRead               — action reads resource data
#   IsWrite              — action mutates/creates/deletes resources
#   IsTaggingOnly        — action only adds/removes tags (lower risk write)
#   IsPermissionManagement — action can change who has access (high risk)
#
# Edge cases included intentionally for defensive coding practice:
#   BrokenActionNoAnnotations   — missing "Annotations" key entirely
#   BrokenActionNoProperties    — "Annotations" exists but is empty
#   BrokenActionNullProperties  — "Properties" key exists but is null
# ============================================================

def get_ec2_metadata_json() -> str:
    return """
    {
        "Name": "ec2",
        "Actions": [
            {
                "Name": "DescribeInstances",
                "Annotations": {
                    "Properties": {
                        "IsList": true,
                        "IsRead": false,
                        "IsWrite": false,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "GetConsoleOutput",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsRead": true,
                        "IsWrite": false,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "StartInstances",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsRead": false,
                        "IsWrite": true,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "CreateTags",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsRead": false,
                        "IsWrite": true,
                        "IsTaggingOnly": true,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "ModifyInstanceAttribute",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsRead": false,
                        "IsWrite": false,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": true
                    }
                }
            },
            {
                "Name": "MixedFlagsAction",
                "Annotations": {
                    "Properties": {
                        "IsList": true,
                        "IsRead": true,
                        "IsWrite": true,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "NoFlagsSet",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsRead": false,
                        "IsWrite": false,
                        "IsTaggingOnly": false,
                        "IsPermissionManagement": false
                    }
                }
            },
            {
                "Name": "BrokenActionNoAnnotations"
            },
            {
                "Name": "BrokenActionNoProperties",
                "Annotations": {}
            },
            {
                "Name": "BrokenActionNullProperties",
                "Annotations": { "Properties": null }
            }
        ]
    }
    """


def load_ec2_metadata() -> dict:
    """Parse and return the EC2 metadata registry as a dict."""
    return json.loads(get_ec2_metadata_json())


def get_action(service_data: dict, action_name: str) -> dict | None:
    """
    Look up a single action by name from a loaded service metadata dict.
    Returns the action dict if found, or None if not found.

    Example:
        data = load_ec2_metadata()
        action = get_action(data, "StartInstances")
        # → {"Name": "StartInstances", "Annotations": {"Properties": {...}}}
    """
    for action in service_data.get("Actions", []):
        if action.get("Name") == action_name:
            return action
    return None


def get_properties(action: dict) -> dict:
    """
    Safely extract the Properties block from an action dict.
    Returns an empty dict if Annotations is missing, empty, or Properties is null.

    This is intentionally defensive — real metadata registries have gaps.

    Example:
        get_properties({"Name": "BrokenActionNoAnnotations"})
        # → {}

        get_properties({"Name": "StartInstances", "Annotations": {"Properties": {"IsWrite": true, ...}}})
        # → {"IsList": false, "IsRead": false, "IsWrite": true, ...}
    """
    return (
        action
        .get("Annotations", {})
        .get("Properties") or {}
    )


# ============================================================
# CALLER CONTEXT
# ============================================================

CALLER_ACCOUNT_ID = "123456789012"


# ============================================================
# PART 1 — classify_principal(principal_block)
# ============================================================
#
# Input: the value of the "Principal" key from one trust statement.
#        It may be:
#          - The string "*"
#          - A dict like {"AWS": "arn:aws:iam::123456789012:role/MyRole"}
#          - A dict like {"Service": "lambda.amazonaws.com"}
#          - A dict like {"AWS": ["arn:...:111111111111:root",
#                                 "arn:...:123456789012:role/Dev"]}
#          - A mix: {"AWS": [...], "Service": [...]}
#
# Output: a list of classification strings (may contain multiple).
#         Possible values: "wildcard", "cross-account",
#                          "same-account", "aws-service", "unknown"
#
# Rules:
#   - "*" anywhere            → "wildcard"
#   - AWS ARN with a 12-digit account ID != "123456789012" → "cross-account"
#   - AWS ARN with account ID == "123456789012"            → "same-account"
#   - Any principal ending in ".amazonaws.com"             → "aws-service"
#   - Anything unrecognized                                → "unknown"
#   - Deduplicate: return each classification at most once
#   - Order does not matter
#
# ARN format reminder:
#   arn:aws:iam::123456789012:role/Dev
#    0    1   2  3      4        5
#   account ID is always at index 4 when split by ":"
#
# Example:
#   classify_principal("*")
#   → ["wildcard"]
#
#   classify_principal({"AWS": "arn:aws:iam::999999999999:root"})
#   → ["cross-account"]
#
#   classify_principal({
#       "AWS": ["arn:aws:iam::123456789012:role/Dev",
#               "arn:aws:iam::999999999999:root"],
#       "Service": "lambda.amazonaws.com"
#   })
#   → ["same-account", "cross-account", "aws-service"]
#
# ============================================================

def classify_principal(principal_block) -> list[str]:
    classifications = set()

    #case 1 if entire prinicipal is *
    if principal_block == "*":
        classifications.add("wildcard")
        return list(classifications)
    
    #case #2 if it is a dict, loop
    for key, value in principal_block.items():
        if isinstance(value, str):
            principals = [value]
        else:
            principals = value
            #spelled wrong lol
        for prinicpal in principals:
            if prinicpal == "*":
                classifications.add("wildcard")

            elif key == "Service":
                if prinicpal.endswith(".amazonaws.com"):
                    classifications.add("aws-service")
                else:
                    classifications.add("unknown")
            elif key == "AWS":
                parts = prinicpal.split(":")
                if len(parts) < 5:
                    classifications.add("unknown")
                else:
                    account_id = parts[4]
                    if account_id == CALLER_ACCOUNT_ID:
                        classifications.add("same-account")
                    else:
                        classifications.add("cross-account")
            else:
                classifications.add("unknown")
    return list(classifications)


# ============================================================
# PART 2 — scan_trust_statement(statement)
# ============================================================
#
# Input: a single statement dict from a trust policy.
#
# Output: a list of finding strings. Each finding starts with
#         its severity label: "CRITICAL", "HIGH", or "INFO".
#
# Checks (run all of them, don't stop early):
#
#   CRITICAL — Principal is or contains "*"
#              Message: "CRITICAL: Trust statement grants access to '*' (anyone)."
#
#   HIGH     — A cross-account principal exists AND the statement
#              has no Condition block containing "sts:ExternalId"
#              Message: 
#
#   INFO     — Statement trusts one or more AWS services
#              Message: "INFO: Statement trusts AWS service principal(s)."
#
# Notes:
#   - A statement may trigger multiple findings.
#   - Use classify_principal() from Part 1.
#   - To check for ExternalId: look for a "Condition" key whose nested
#     structure contains "sts:ExternalId" at any operator level, e.g.:
#       {"StringEquals": {"sts:ExternalId": "abc123"}}
#
# Example:
#   scan_trust_statement({
#       "Effect": "Allow",
#       "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
#       "Action": "sts:AssumeRole"
#   })
#   → ["HIGH: Cross-account principal without ExternalId condition."]
#
# ============================================================

def has_external_id_condition(condition_block: dict) -> bool:
    """
    Helper: return True if condition_block contains "sts:ExternalId"
    at any nesting level (under any operator key).

    Example:
        has_external_id_condition({"StringEquals": {"sts:ExternalId": "abc"}})
        → True

        has_external_id_condition({"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
        → False
    """
    for operator_key, inner_dict in condition_block.items():
        if "sts:ExternalId" in inner_dict:
            return True
    return False
    
    pass


def scan_trust_statement(statement: dict) -> list[str]:
    findings = []
    #get principcal from statement and run it through classify prinicpal
    prinicpal_block = statement.get("Principal")
    classifications = classify_principal(prinicpal_block)

    #case 1 wildcard
    if "wildcard" in classifications:
        findings.append("CRITICAL: Trust statement grants access to '*' (anyone).")
    #case 2 - cross acc without externalid
    if "cross-account" in classifications:
        condition_block = statement.get("Condition", {})
        if has_external_id_condition(condition_block) is False:
            findings.append("HIGH: Cross-account principal without ExternalId condition.")
    #case 3 
    if "aws-service" in classifications:
        findings.append("INFO: Statement trusts AWS service principal(s).")
    
    return findings



# ============================================================
# PART 3 — validate_trust_policy(policy)
# ============================================================
#
# Input: a full trust policy dict, e.g.:
#   {
#     "Version": "2012-10-17",
#     "Statement": [ ...list of statements... ]
#   }
#
# Output: a dict with this exact structure:
#   {
#     "valid": True or False,
#     "findings": ["CRITICAL: ...", "HIGH: ...", "INFO: ..."],
#     "summary": "X issue(s) found across Y statement(s)."
#   }
#
# Rules:
#   - Collect all findings across all statements.
#   - "valid" is False if any finding starts with "CRITICAL" or "HIGH".
#     INFO findings alone do not make the policy invalid.
#   - "summary" uses the total finding count and total statement count.
#   - If "Statement" key is missing or empty, return:
#       valid=True, findings=[], summary="0 issue(s) found across 0 statement(s)."
#
# ============================================================

def validate_trust_policy(policy: dict) -> dict:
    statements = policy.get("Statement", [])

    #if statements empty, return early
    if not statements:
        return {
        "valid": True,
        "findings": [],
        "summary": "0 issue(s) found across 0 statement(s)."
        }
    master_findings = []
    for statement in statements:
        findings = scan_trust_statement(statement)
        #master_findings = findings.extend()
        master_findings.extend(findings)

    is_valid = True
    for findings in master_findings:
        if findings.startswith("HIGH") or findings.startswith("CRITICAL"):
            is_valid = False
            #break - for better performance since it is false and result would be the same but good
            break

    count = len(master_findings)
    total = len(statements)
    summary = f"{count} issue(s) found across {total} statement(s)."

    return {
        "valid" : is_valid,
        "findings" : master_findings,
        "summary" : summary
    }
    



# ============================================================
# TEST CASES — do not modify, use these to check your work
# ============================================================

if __name__ == "__main__":

    # ----------------------------------------------------------
    # Metadata registry sanity checks
    # ----------------------------------------------------------
    ec2 = load_ec2_metadata()

    # get_action returns the right action
    action = get_action(ec2, "StartInstances")
    assert action is not None
    assert action["Name"] == "StartInstances"

    # get_action returns None for unknown actions
    assert get_action(ec2, "NonExistentAction") is None

    # get_properties returns correct data for a normal action
    props = get_properties(get_action(ec2, "StartInstances"))
    assert props["IsWrite"] == True
    assert props["IsRead"] == False

    # get_properties handles all broken metadata cases gracefully
    assert get_properties(get_action(ec2, "BrokenActionNoAnnotations")) == {}
    assert get_properties(get_action(ec2, "BrokenActionNoProperties")) == {}
    assert get_properties(get_action(ec2, "BrokenActionNullProperties")) == {}

    # get_properties handles a mixed-flags action
    mixed_props = get_properties(get_action(ec2, "MixedFlagsAction"))
    assert mixed_props["IsList"] == True
    assert mixed_props["IsWrite"] == True

    print("Metadata tests passed.")

    # ----------------------------------------------------------
    # Part 1 — classify_principal
    # ----------------------------------------------------------
    assert sorted(classify_principal("*")) == ["wildcard"]

    assert sorted(classify_principal(
        {"AWS": "arn:aws:iam::123456789012:role/Dev"}
    )) == ["same-account"]

    assert sorted(classify_principal(
        {"AWS": "arn:aws:iam::999999999999:root"}
    )) == ["cross-account"]

    assert sorted(classify_principal(
        {"Service": "lambda.amazonaws.com"}
    )) == ["aws-service"]

    assert sorted(classify_principal({
        "AWS": [
            "arn:aws:iam::123456789012:role/Dev",
            "arn:aws:iam::999999999999:root"
        ],
        "Service": "lambda.amazonaws.com"
    })) == ["aws-service", "cross-account", "same-account"]

    print("Part 1 tests passed.")

    # ----------------------------------------------------------
    # Part 2 — scan_trust_statement
    # ----------------------------------------------------------
    assert scan_trust_statement({
        "Effect": "Allow",
        "Principal": "*",
        "Action": "sts:AssumeRole"
    }) == ["CRITICAL: Trust statement grants access to '*' (anyone)."]

    assert scan_trust_statement({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "sts:AssumeRole"
    }) == ["HIGH: Cross-account principal without ExternalId condition."]

    assert scan_trust_statement({
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
        "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"sts:ExternalId": "secret-99"}}
    }) == []

    assert scan_trust_statement({
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"
    }) == ["INFO: Statement trusts AWS service principal(s)."]

    print("Part 2 tests passed.")

    # ----------------------------------------------------------
    # Part 3 — validate_trust_policy
    # ----------------------------------------------------------
    result = validate_trust_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::999999999999:root"},
                "Action": "sts:AssumeRole"
            },
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    assert result["valid"] == False
    assert any("HIGH" in f for f in result["findings"])
    assert any("INFO" in f for f in result["findings"])
    assert result["summary"] == "2 issue(s) found across 2 statement(s)."

    result2 = validate_trust_policy({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:role/Dev"},
                "Action": "sts:AssumeRole"
            }
        ]
    })
    assert result2["valid"] == True
    assert result2["findings"] == []
    assert result2["summary"] == "0 issue(s) found across 1 statement(s)."

    result3 = validate_trust_policy({})
    assert result3["valid"] == True
    assert result3["findings"] == []
    assert result3["summary"] == "0 issue(s) found across 0 statement(s)."

    print("Part 3 tests passed.")

    print("\nAll tests passed!")