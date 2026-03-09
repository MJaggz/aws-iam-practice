#!/usr/bin/env python3
"""
Practice Problem #3: EC2 IAM Access Level Classifier

You are given mocked IAM metadata for EC2 actions.

Your task:
Implement classify_ec2_action(action_name) to return ONE of these strings:

    "ReadOnly"
    "WriteLike"
    "Unknown"

Classification rules:
----------------------------------------------------------------
Return "ReadOnly" if:
    - IsList == True
    OR
    - IsRead == True

Return "WriteLike" if:
    - IsWrite == True
    OR
    - IsTaggingOnly == True
    OR
    - IsPermissionManagement == True

Return "Unknown" if:
    - the action is not found
    - OR the action metadata is malformed / missing enough information
    - OR none of the above flags are true

Priority rule:
    - If an action has ANY write-like flag, return "WriteLike"
    - Else if it has any read-only flag, return "ReadOnly"
    - Else return "Unknown"

Requirements:
----------------------------------------------------------------
- Parse the JSON using json.loads
- Loop through data["Actions"]
- Find the action with Name == action_name
- Safely navigate nested dictionaries
- Handle missing keys and null values safely
- Do NOT hardcode answers
"""

import json


def get_ec2_json() -> str:
    """
    Mock EC2 IAM metadata.

    This dataset includes:
    - normal actions
    - mixed-flag action
    - malformed actions
    - action with no true flags
    """
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


def classify_ec2_action(action_name: str) -> str:
    """
    Returns one of:
        "ReadOnly"
        "WriteLike"
        "Unknown"

    Rules:
    - WriteLike wins over ReadOnly if both appear
    - Unknown if action not found, malformed, or no flags are true
    """

    data = json.loads(get_ec2_json())

    # ----------------------------------
    # YOUR CODE GOES HERE
    # ----------------------------------

    for action in data["Actions"]:
        if action["Name"] == action_name:
            annotations = action.get("Annotations", {})
            properties = annotations.get("Properties", {})
            if properties is None: 
                properties = {}
            is_read = properties.get("IsRead", False)
            is_list = properties.get("IsList", False)
            is_write = properties.get("IsWrite", False)
            is_tagging = properties.get("IsTaggingOnly", False)
            is_perm = properties.get("IsPermissionManagement", False)

            if is_write or is_tagging or is_perm:
                return "WriteLike"
            elif is_list or is_read:
                return "ReadOnly"
    
            return "Unknown"






    pass


if __name__ == "__main__":
    tests = [
        "DescribeInstances",
        "GetConsoleOutput",
        "StartInstances",
        "CreateTags",
        "ModifyInstanceAttribute",
        "MixedFlagsAction",
        "NoFlagsSet",
        "BrokenActionNoAnnotations",
        "BrokenActionNoProperties",
        "BrokenActionNullProperties",
        "DoesNotExist"
    ]

    for t in tests:
        print(f"{t:30} -> {classify_ec2_action(t)}")