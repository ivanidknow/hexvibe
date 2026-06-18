# Vulnerable: IAM-AWS-AWSDeadlineCloud-WorkerHost
{
  "Action": [
    "deadline:CreateWorker",
    "deadline:AssumeFleetRoleForWorker"
  ],
  "Condition": {
    "StringEquals": {
      "aws:PrincipalAccount": "${aws:ResourceAccount}"
...
  "Sid": "JoinFleetPermissions"
}
