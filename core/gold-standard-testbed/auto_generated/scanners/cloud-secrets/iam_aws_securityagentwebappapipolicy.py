# Vulnerable: IAM-AWS-SecurityAgentWebAppAPIPolicy
{
  "Action": [
    "securityagent:ListAgentInstances",
    "securityagent:ListControls"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  "Sid": "ApplicationAccess"
}
