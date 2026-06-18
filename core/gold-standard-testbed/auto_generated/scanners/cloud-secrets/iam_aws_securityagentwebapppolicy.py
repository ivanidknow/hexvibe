# Vulnerable: IAM-AWS-SecurityAgentWebAppPolicy
{
  "Action": [
    "securityagent:ListAgentSpaces",
    "securityagent:ListSecurityRequirements"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  "Sid": "ApplicationAccess"
}
