# Vulnerable: IAM-AWS-CloudWatchLambdaApplicationSignalsExecutionRolePolicy
{
  "Action": [
    "xray:PutTraceSegments"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
    }
...
  "Sid": "CloudWatchApplicationSignalsXrayWritePermissions"
}
