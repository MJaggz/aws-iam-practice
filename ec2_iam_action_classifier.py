#!/usr/bin/env python3
"""
Practice Problem: EC2 IAM Action Classification

You are given mocked IAM metadata for EC2 actions.

Your task:
Implement get_write_actions() so that it returns a list
of action names that represent write operations.

Write operations are defined as:
    - IsWrite == True
    OR
    - IsPermissionManagement == True

Do NOT hardcode answers.
You must:
    - Parse JSON
    - Loop through actions
    - Inspect nested dictionary properties
"""

import json


def get_ec2_json() -> str:
    """
    Mock function returning EC2 IAM action metadata.
    In real AWS systems this comes from the service authorization reference.
    """

    return """
    {
        "Name": "ec2",
        "Actions": [
            {
                "Name": "StartInstances",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsPermissionManagement": false,
                        "IsTaggingOnly": false,
                        "IsWrite": true
                    }
                }
            },
            {
                "Name": "StopInstances",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsPermissionManagement": false,
                        "IsTaggingOnly": false,
                        "IsWrite": true
                    }
                }
            },
            {
                "Name": "DescribeInstances",
                "Annotations": {
                    "Properties": {
                        "IsList": true,
                        "IsPermissionManagement": false,
                        "IsTaggingOnly": false,
                        "IsWrite": false
                    }
                }
            },
            {
                "Name": "CreateTags",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsPermissionManagement": false,
                        "IsTaggingOnly": true,
                        "IsWrite": true
                    }
                }
            },
            {
                "Name": "ModifyInstanceAttribute",
                "Annotations": {
                    "Properties": {
                        "IsList": false,
                        "IsPermissionManagement": true,
                        "IsTaggingOnly": false,
                        "IsWrite": false
                    }
                }
            }
        ]
    }
    """


def get_write_actions() -> list:
    """
    Returns:
        A list of EC2 action names that are considered write operations.

    Requirements:
        - Parse the JSON
        - Loop through each action
        - Inspect nested properties
        - Append matching action names to a list
        - Return the list
    """

    data = json.loads(get_ec2_json())

    # -------------------------------
    write_actions = []
    for action in data["Actions"]:
        ##action = data["Actions"] not needed since overwriting prev line
        properties = action["Annotations"]["Properties"]
        is_write = properties["IsWrite"]
        is_perm = properties["IsPermissionManagement"]

        if is_write or is_perm:
            write_actions.append(action["Name"])
    return write_actions

    

    # -------------------------------

    pass


if __name__ == "__main__":
    """
    Simple test runner.
    This is just for local testing.
    """

    result = get_write_actions()
    print("Write Actions Found:")
    print(result)
