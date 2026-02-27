#!/usr/bin/env python3
"""
Harder Practice Problem #2: EC2 IAM Read-Only Classifier

You are given mocked IAM metadata for EC2 actions.

Your task:
Implement is_read_only_ec2(action_name) to return a boolean:

Return True  -> if the action is considered READ-ONLY
Return False -> otherwise (write-like or unknown)

Read-only definition:
    - IsList == True OR IsRead == True

Write-like definition:
    - IsWrite == True OR IsTaggingOnly == True OR IsPermissionManagement == True

Requirements:
    - Parse JSON using json.loads
    - Loop through data["Actions"]
    - Find the action with Name == action_name
    - Handle missing keys safely (some entries are incomplete)
    - If action not found, return False
"""

import json


def get_ec2_json() -> str:
    """
    Mock EC2 IAM action metadata.
    NOTE: This dataset intentionally includes actions with missing nested keys
    to simulate real-world messy/partial metadata.
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


def is_read_only_ec2(action_name: str) -> bool:
    """
    Returns True if the given EC2 IAM action is read-only, else False.

    Requirements reminder:
    - Loop through Actions
    - Find the action by Name
    - Safely navigate nested dictionaries
    - Apply read/write rules described above
    - Unknown or malformed actions -> return False
    """

    data = json.loads(get_ec2_json())

    # -------------------------------
    # YOUR CODE GOES HERE
    ##read_actions = []
    for action in data["Actions"]:
        if action["Name"] == action_name:
            annotations = action.get("Annotations", {})
            properties = annotations.get("Properties", {})
            if properties is None: # "or {}" instead of if statement
                properties = {}
            is_read = properties.get("IsRead", False)
            is_list = properties.get("IsList", False)
            if is_read or is_list:
                return True
    return False

        #could also do
        #is_write = action.get("Annotations", {}) \
                 #.get("Properties", {}) \
                # .get("IsWrite", False)

    # -------------------------------
   

    pass


if __name__ == "__main__":
    # Local test runner (you can change these inputs)
    tests = [
        "DescribeInstances",
        "GetConsoleOutput",
        "StartInstances",
        "CreateTags",
        "ModifyInstanceAttribute",
        "DoesNotExist",
        "BrokenActionNoAnnotations",
        "BrokenActionNoProperties",
        "BrokenActionNullProperties"
    ]

    for t in tests:
        print(f"{t:30} -> {is_read_only_ec2(t)}")
