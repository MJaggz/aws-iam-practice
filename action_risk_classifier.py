# ============================================================
# PROJECT  : aws-security-toolkit
# FILE     : problems/problem_08_action_risk_classifier.py
# PROBLEM  : Action Risk Classifier — "How Dangerous Is This Policy?"
# ============================================================
# Difficulty  : Medium
# Topic       : Action metadata, risk classification, policy analysis
# Style       : AWS Interview / Internship Simulation
# Concepts    : Action format (service:Action), risk tiers,
#               wildcard actions, metadata registry lookups,
#               defensive coding, policy risk profiling
# ============================================================
#
# BACKGROUND
# ----------
# Not all IAM actions carry the same risk. An action that lists
# resources is far less dangerous than one that modifies who has
# access to them. Real AWS tooling like IAM Access Analyzer and
# internal cloud governance scanners cross-reference policy actions
# against a metadata registry to produce a risk profile before
# a role is deployed.
#
# In this problem you will build an action risk classifier that:
#   1. Looks up each action in the EC2 metadata registry
#   2. Assigns it a risk tier based on its properties
#   3. Summarizes the overall risk of a set of actions
#
# This classifier is the natural next step after Problem 7 —
# combined with the trust policy validator, you now have two
# halves of a complete role security scanner.
#
# RISK TIERS (in priority order, highest to lowest)
# --------------------------------------------------
#   "wildcard"             → action is "ec2:*" (all actions)
#   "permission-management"→ IsPermissionManagement is True
#   "write"                → IsWrite is True
#   "tagging"              → IsTaggingOnly is True
#   "read"                 → IsRead or IsList is True
#   "unknown"              → metadata missing or no flags set
#
# ACTION FORMAT
# -------------
# IAM actions follow the format "service:ActionName"
# Example: "ec2:StartInstances", "ec2:DescribeInstances"
# The part before ":" is the service, after ":" is the action name.
#
# ============================================================


import json


# ============================================================
# METADATA REGISTRY
# ============================================================
# Reference table of EC2 actions and their security-relevant
# properties. Do not modify this section.
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
#   NoFlagsSet                  — all flags are False
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

    Example:
        get_properties({"Name": "BrokenActionNoAnnotations"})
        # → {}

        get_properties({"Name": "StartInstances", "Annotations": {"Properties": {"IsWrite": True, ...}}})
        # → {"IsList": False, "IsRead": False, "IsWrite": True, ...}
    """
    return (
        action
        .get("Annotations", {})
        .get("Properties") or {}
    )


# ============================================================
# PART 1 — classify_action(service_data, action_string)
# ============================================================
#
# Input:
#   service_data  — loaded metadata dict from load_ec2_metadata()
#   action_string — a single action string like "ec2:StartInstances"
#
# Output: a single risk tier string, one of:
#   "wildcard", "permission-management", "write",
#   "tagging", "read", "unknown"
#
# Rules:
#   - Split action_string on ":" to get the action name
#   - If action name is "*", return "wildcard" immediately
#   - Look up the action in service_data using get_action()
#   - If not found, return "unknown"
#   - Use get_properties() to safely get the properties
#   - Check flags in this priority order:
#       1. IsPermissionManagement → "permission-management"
#       2. IsWrite                → "write"
#       3. IsRead or IsList       → "read"
#       4. IsTaggingOnly          → "tagging"
#       5. none of the above      → "unknown"
#
# Note: IsTaggingOnly is checked AFTER IsWrite because in real
#       AWS metadata, tagging actions often have IsWrite = True too.
#       Priority order ensures the most specific tier wins.
#
# Example:
#   classify_action(ec2, "ec2:StartInstances")    → "write"
#   classify_action(ec2, "ec2:DescribeInstances") → "read"
#   classify_action(ec2, "ec2:ModifyInstanceAttribute") → "permission-management"
#   classify_action(ec2, "ec2:*")                 → "wildcard"
#   classify_action(ec2, "ec2:NonExistent")       → "unknown"
#
# ============================================================

def classify_action(service_data: dict, action_string: str) -> str:
    #split action_string into two parts something like ["ec2", "ec2:StartInstances"]
    parts = action_string.split(":")
    action_name = parts[1]

    #rule 1 wildcard
    if action_name == "*":
        return "wildcard"
    
    #look up the action
    action = get_action(service_data, action_name)

    if action is None:
        return "unknown"
    
    props = get_properties(action)

    #check by priority
    if props.get("IsPermissionManagement") is True:
        return "permission-management"
    
    if props.get("IsWrite") is True:
        return "write"
    
    if props.get("IsRead") or props.get("IsList") is True:
        return "read"
    
    if props.get("IsTaggingOnly ") is True:
        return "tagging"
    
    return "unknown"


    


# ============================================================
# PART 2 — classify_actions(service_data, action_list)
# ============================================================
#
# Input:
#   service_data — loaded metadata dict from load_ec2_metadata()
#   action_list  — a list of action strings
#
# Output: a dict mapping each action string to its risk tier
#
# Example:
#   classify_actions(ec2, [
#       "ec2:StartInstances",
#       "ec2:DescribeInstances",
#       "ec2:ModifyInstanceAttribute",
#       "ec2:*"
#   ])
#   →
#   {
#       "ec2:StartInstances": "write",
#       "ec2:DescribeInstances": "read",
#       "ec2:ModifyInstanceAttribute": "permission-management",
#       "ec2:*": "wildcard"
#   }
#
# ============================================================

def classify_actions(service_data: dict, action_list: list) -> dict:
    #create empty dict
    results = {}

    for action_string in action_list:
        results[action_string] = classify_action(service_data, action_string)

    return results



# ============================================================
# PART 3 — summarize_risk(classified_actions)
# ============================================================
#
# Input: the dict returned by classify_actions()
#
# Output: a risk summary dict with this exact structure:
#   {
#       "highest_risk": "permission-management",  # or None if no actions
#       "tiers": {
#           "permission-management": ["ec2:ModifyInstanceAttribute"],
#           "write": ["ec2:StartInstances"],
#           "read": ["ec2:DescribeInstances"],
#           "tagging": [],
#           "wildcard": ["ec2:*"],
#           "unknown": []
#       },
#       "safe_to_deploy": True or False
#   }
#
# Rules:
#   - Sort each action into its tier bucket
#   - highest_risk is the most dangerous tier that has at least one action
#     use this risk order: wildcard → permission-management → write
#                          → tagging → read → unknown
#   - safe_to_deploy is False if any action is "permission-management"
#     or "wildcard". Everything else is considered safe.
#   - If classified_actions is empty, highest_risk is None
#     and safe_to_deploy is True
#
# ============================================================

def summarize_risk(classified_actions: dict) -> dict:
    tiers = {
        "permission-management": [],
        "write": [],
        "read": [],
        "tagging": [],
        "wildcard": [],
        "unknown": []
    }

    #risk
    risk_order = [
        "wildcard",
        "permission-management",
        "write",
        "tagging",
        "read",
        "unknown"
    ]
    #loop through actions and sort 
    for action, tier in classified_actions.items():
        tiers[tier].append(action)

    highest_risk = None
    for tier in risk_order:
        if len(tiers[tier]) > 0:
            highest_risk = tier
            break
    #if safe to deply is false if any perms managemement or wildcat exists

    safe_to_deploy = (
        len(tiers["permission-management"]) == 0
        and len(tiers["wildcard"]) == 0
    )
        

    return {
        "highest_risk": highest_risk,
        "tiers": tiers,
        "safe_to_deploy": safe_to_deploy
        }






# ============================================================
# TEST CASES — do not modify, use these to check your work
# ============================================================

if __name__ == "__main__":

    ec2 = load_ec2_metadata()

    # ----------------------------------------------------------
    # Part 1 — classify_action
    # ----------------------------------------------------------

    # normal cases
    assert classify_action(ec2, "ec2:StartInstances") == "write"
    assert classify_action(ec2, "ec2:DescribeInstances") == "read"
    assert classify_action(ec2, "ec2:GetConsoleOutput") == "read"
    assert classify_action(ec2, "ec2:ModifyInstanceAttribute") == "permission-management"
    assert classify_action(ec2, "ec2:CreateTags") == "write"

    # wildcard
    assert classify_action(ec2, "ec2:*") == "wildcard"

    # unknown action not in registry
    assert classify_action(ec2, "ec2:NonExistentAction") == "unknown"

    # broken metadata cases — all should return "unknown"
    assert classify_action(ec2, "ec2:BrokenActionNoAnnotations") == "unknown"
    assert classify_action(ec2, "ec2:BrokenActionNoProperties") == "unknown"
    assert classify_action(ec2, "ec2:BrokenActionNullProperties") == "unknown"
    assert classify_action(ec2, "ec2:NoFlagsSet") == "unknown"

    # mixed flags — IsWrite and IsRead both True, IsWrite wins
    assert classify_action(ec2, "ec2:MixedFlagsAction") == "write"

    print("Part 1 tests passed.")

    # ----------------------------------------------------------
    # Part 2 — classify_actions
    # ----------------------------------------------------------

    result = classify_actions(ec2, [
        "ec2:StartInstances",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:*",
        "ec2:NonExistentAction"
    ])

    assert result["ec2:StartInstances"] == "write"
    assert result["ec2:DescribeInstances"] == "read"
    assert result["ec2:ModifyInstanceAttribute"] == "permission-management"
    assert result["ec2:*"] == "wildcard"
    assert result["ec2:NonExistentAction"] == "unknown"

    # empty list returns empty dict
    assert classify_actions(ec2, []) == {}

    print("Part 2 tests passed.")

    # ----------------------------------------------------------
    # Part 3 — summarize_risk
    # ----------------------------------------------------------

    classified = classify_actions(ec2, [
        "ec2:StartInstances",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:CreateTags",
        "ec2:*"
    ])

    summary = summarize_risk(classified)

    assert summary["highest_risk"] == "wildcard"
    assert summary["safe_to_deploy"] == False
    assert "ec2:ModifyInstanceAttribute" in summary["tiers"]["permission-management"]
    assert "ec2:StartInstances" in summary["tiers"]["write"]
    assert "ec2:DescribeInstances" in summary["tiers"]["read"]
    assert "ec2:*" in summary["tiers"]["wildcard"]

    # safe policy — only read actions
    safe_classified = classify_actions(ec2, [
        "ec2:DescribeInstances",
        "ec2:GetConsoleOutput"
    ])
    safe_summary = summarize_risk(safe_classified)
    assert safe_summary["highest_risk"] == "read"
    assert safe_summary["safe_to_deploy"] == True

    # empty input
    empty_summary = summarize_risk({})
    assert empty_summary["highest_risk"] == None
    assert empty_summary["safe_to_deploy"] == True

    print("Part 3 tests passed.")

    print("\nAll tests passed!")