#!/usr/bin/env python3
"""
Practice Problem #5: EC2 IAM Bulk Analyzer

You are given mocked IAM metadata for EC2 actions.

You must implement TWO functions:

1) classify_ec2_action(action: dict) -> str
   - Takes ONE action dictionary
   - Returns:
        "ReadOnly"
        "WriteLike"
        "Unknown"

2) get_actions_by_classification(classification: str) -> list
   - Returns a list of action names matching that classification

Classification rules:
---------------------------------------------
WriteLike:
    IsWrite OR IsTaggingOnly OR IsPermissionManagement

ReadOnly:
    IsList OR IsRead

Unknown:
    none of the above OR malformed data

Priority:
    WriteLike > ReadOnly > Unknown
"""

import json


def get_ec2_json():
    return """
    {
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
                        "IsWrite": true
                    }
                }
            },
            {
                "Name": "CreateTags",
                "Annotations": {
                    "Properties": {
                        "IsTaggingOnly": true
                    }
                }
            },
            {
                "Name": "ModifyInstanceAttribute",
                "Annotations": {
                    "Properties": {
                        "IsPermissionManagement": true
                    }
                }
            },
            {
                "Name": "BrokenAction",
                "Annotations": {}
            },
            {
                "Name": "NullPropsAction",
                "Annotations": { "Properties": null }
            }
        ]
    }
    """


# -----------------------------
# Function 1 (Single Action)
# -----------------------------
def classify_ec2_action(action: dict) -> str:
    """
    Analyze ONE action dictionary and return classification.
    """
    # YOUR CODE HERE
    annotations = action.get("Annotations", {})
    properties = annotations.get("Properties", {})

    if properties is None:
        properties = {}
    is_list = properties.get("IsList", False)
    is_read = properties.get("IsRead", False)
    is_write = properties.get("IsWrite", False)
    is_tag = properties.get("IsTaggingOnly", False)
    is_perm = properties.get("IsPermissionManagement", False)

    if is_write or is_tag or is_perm:
        return "WriteLike"
    elif is_list or is_read:
        return "ReadOnly"
    else:
        return "Unknown"
    pass


# -----------------------------
# Function 2 (Bulk Analyzer)
# -----------------------------
def get_actions_by_classification(classification: str) -> list:
    """
    Return list of action names that match the given classification.
    """
    data = json.loads(get_ec2_json())

    # YOUR CODE HERE
    #loop through all actions
    results =[]
    for action in data["Actions"]:
        classification_result = classify_ec2_action(action)
        #compare result with input classification
        if classification_result == classification:
            results.append(action)
    return results
    pass


# -----------------------------
# Test Runner
# -----------------------------
if __name__ == "__main__":
    print("ReadOnly:")
    print(get_actions_by_classification("ReadOnly"))

    print("\nWriteLike:")
    print(get_actions_by_classification("WriteLike"))

    print("\nUnknown:")
    print(get_actions_by_classification("Unknown"))