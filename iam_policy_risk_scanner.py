#!/usr/bin/env python3
RULE_STAR_ACTION = "RULE_STAR_ACTION"
RULE_STAR_RESOURCE = "RULE_STAR_RESOURCE"
RULE_IAM_ADMIN = "RULE_IAM_ADMIN"
RULE_WILDCARD_PRINCIPAL = "RULE_WILDCARD_PRINCIPAL"
"""
Practice Problem: IAM Policy Risk Scanner

You are given a mocked IAM-style policy document.

Your task:
Implement two functions:

1) scan_statement(stmt: dict, index: int) -> list
   - Scans ONE statement
   - Returns a list of findings for that statement

2) scan_policy(policy: dict) -> list
   - Scans the whole policy
   - Loops through all statements
   - Uses scan_statement(...)
   - Returns a combined list of findings

A finding should look like:
{
    "RuleId": str,
    "StatementIndex": int,
    "Message": str
}

Risk rules:
------------------------------------------------
RULE_STAR_ACTION:
    Effect == "Allow" AND Action contains "*"

RULE_STAR_RESOURCE:
    Effect == "Allow" AND Resource contains "*"

RULE_IAM_ADMIN:
    Effect == "Allow" AND Action contains "iam:*"

RULE_WILDCARD_PRINCIPAL:
    Principal == "*"
    OR Principal contains {"AWS": "*"}
    OR Principal contains {"Service": "*"}
"""

import json


def get_policy_json() -> str:
    return """
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SafeReadOnly",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::my-bucket/*"]
            },
            {
                "Sid": "TooBroadAction",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::my-bucket/*"
            },
            {
                "Sid": "TooBroadResource",
                "Effect": "Allow",
                "Action": "ec2:StartInstances",
                "Resource": "*"
            },
            {
                "Sid": "IAMAdminLike",
                "Effect": "Allow",
                "Action": ["iam:*", "s3:GetObject"],
                "Resource": "*"
            },
            {
                "Sid": "TrustLikeWildcard",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            },
            {
                "Sid": "ServiceWildcardTrust",
                "Effect": "Allow",
                "Principal": {
                    "Service": "*"
                },
                "Action": "sts:AssumeRole"
            },
            {
                "Sid": "BrokenStatement",
                "Effect": "Allow"
            }
        ]
    }
    """


def as_list(value):
    """
    If value is already a list, return it.
    Otherwise return [value].
    """
    if isinstance(value, list):
        return value
    return [value]


def scan_statement(stmt: dict, index: int) -> list:
    """
    Scan ONE statement and return a list of findings.
    """
    #initalize a list to store findings
    findings = []
    #get effect from stmt and set the default as None
    effect = stmt.get("Effect")
    #if effect is None:
        #effect = {}
    #get actions and resource from stmt and normalize into a list using as_list
    actions = as_list(stmt.get("Action", []))
    resources = as_list(stmt.get("Resource", []))
    #get prinicpal from stmt
    principal = stmt.get("Principal", {})

    #rules
    if effect == "Allow":
        #if actions.__contains__("*"):
        if "*" in actions:
            findings.append({
                "RuleId": RULE_STAR_ACTION,
                "StatementIndex": index,
                "Message": "Statement allows all actions ('Action': '*'), which is overly permissive."
            })
    if effect == "Allow":
        #if resources.__contains__("*"):
        if "*" in resources:
            findings.append({
                "RuleId": RULE_STAR_RESOURCE,
                "StatementIndex": index,
                "Message": "Statement applies to all resources ('Resource': '*'), which is overly permissive."
            })
    if effect == "Allow":
        #if actions.__contains__("iam:*"):
        if "iam:*" in actions:
            findings.append({
                "RuleId": RULE_IAM_ADMIN,
                "StatementIndex": index,
                "Message": "Statement allows all actions ('Action': '*'), which is overly permissive."
            })
    if principal is not None:
        #case 1 prinicpal is "*"
        if principal == "*":
            findings.append({
                "RuleId": RULE_WILDCARD_PRINCIPAL, 
                "StatementIndex": index,
                "Message": "Statement allows wildcard principa. which permits access from any principal"
            })
            #case 2 if prinicpal is a dict
        elif isinstance(principal, dict):
            if "AWS" in principal:
                aws_value = principal["AWS"]
                if aws_value == "*" or "*" in as_list(aws_value):
                    findings.append({
                "RuleId": RULE_WILDCARD_PRINCIPAL, 
                "StatementIndex": index,
                "Message": "Statement allows wildcard principa. which permits access from any principal"
            })
            if "Service" in principal:
                service_value = principal["Service"]
                if service_value == "*" or "*" in as_list(service_value):
                    findings.append({
                    "RuleId": RULE_WILDCARD_PRINCIPAL, 
                    "StatementIndex": index,
                    "Message": "Statement allows wildcard principaL. which permits access from any principal"
                })
    return findings


def scan_policy(policy: dict) -> list:
    """
    Scan the whole policy and return all findings.
    """
    findings = []

    #statement = as_list(policy.get("Statement", []))
    statement = policy.get("Statement", [])
    if statement is None:
        statement = []
    statements = as_list(statement)

    #loop through each statement with idx
    for index, stmt in enumerate(statements):
        statement_findings = scan_statement(stmt, index)
        #findings.append(statement_findings)
        #extend not append
        findings.extend(statement_findings)
    return findings


if __name__ == "__main__":
    policy = json.loads(get_policy_json())
    findings = scan_policy(policy)

    print("Policy Findings:")
    for finding in findings:
        print(finding)