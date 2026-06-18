# Vulnerable: IAM-AWS-AWSSecurityAgentWebAppPolicy
{
  "Action": [
    "securityagent:ListAgentSpaces",
    "securityagent:ListSecurityRequirements",
    "securityagent:ListTargetDomains",
    "securityagent:BatchGetTargetDomains"
  ],
  "Condition": {
...
  "Sid": "ApplicationAccess"
}
