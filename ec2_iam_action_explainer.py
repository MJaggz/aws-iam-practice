#!/usr/bin/env python3
"""
Practice Problem #4: EC2 IAM Action Explainer

You are given mocked IAM metadata for EC2 actions.

Your task:
Implement explain_ec2_action(action_name) so that it returns a dictionary
describing the action and its classification.

Return dictionary format:
{
    "ActionName": str,
    "Found": bool,
    "Classification": str,   # "ReadOnly", "WriteLike", or "Unknown"
    "Flags": {
        "IsList": bool,
        "IsRead": bool,
        "IsWrite": bool,
        "IsTaggingOnly": bool,
        "IsPermissionManagement": bool
    }
}

Classification rules:
----------------------------------------------------------------
Return "WriteLike" if:
    - IsWrite == True
    OR
    - IsTaggingOnly == True
    OR
    - IsPermissionManagement == True

Return "ReadOnly" if:
    - IsList == True
    OR
    - IsRead == True

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


def explain_ec2_action(action_name: str) -> dict:
    """
    Returns a dictionary explaining the EC2 action classification.
    """

    data = json.loads(get_ec2_json())

    # ----------------------------------
    # YOUR CODE GOES HERE
    # ----------------------------------
    #init starting dict for now 
    result = {
    "ActionName": action_name,
    "Found": False,
    "Classification": "Unknown",
    "Flags": {
        "IsList": False,
        "IsRead": False,
        "IsWrite": False,
        "IsTaggingOnly": False,
        "IsPermissionManagement": False
    }
}
    for action in data["Actions"]:
        if action["Name"] == action_name:
            result["Found"] = True
            annotations = action.get("Annotations", {})
            properties = annotations.get("Properties", {})
            if properties is None: 
                properties = {}
            is_read = properties.get("IsRead", False)
            is_list = properties.get("IsList", False)
            is_write = properties.get("IsWrite", False)
            is_tagging = properties.get("IsTaggingOnly", False)
            is_perm = properties.get("IsPermissionManagement", False)

            #store the flags inside the result dict
            result["Flags"]["IsRead"] = is_read
            result["Flags"]["IsList"] = is_list
            result["Flags"]["IsWrite"] = is_write
            result["Flags"]["IsTaggingOnly"] = is_tagging
            result["Flags"]["IsPermissionManagement"] = is_perm

            if is_write or is_tagging or is_perm:
                result["Classification"] = "WriteLike"
            elif is_list or is_read:
                result["Classification"] = "ReadOnly"
            else:
                result["Classification"] = "Unknown"
            return result
    return result



    # for action in data["Actions"]:
    #     if action["Name"] == action_name:
    #      annotations = action.get("Annotations", {})
    #      properties = annotations.get("Properties", {})
    #      if properties is None: 
    #              properties = {}
    #      is_read = properties.get("IsRead", False)
    #      is_list = properties.get("IsList", False)
    #      is_write = properties.get("IsWrite", False)
    #      is_tagging = properties.get("IsTaggingOnly", False)
    #      is_perm = properties.get("IsPermissionManagement", False)
    



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
        print(f"{t}:")
        print(explain_ec2_action(t))
        print("-" * 50)