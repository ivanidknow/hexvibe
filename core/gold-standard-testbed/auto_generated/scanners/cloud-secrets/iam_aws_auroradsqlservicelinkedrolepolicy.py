# Vulnerable: IAM-AWS-AuroraDsqlServiceLinkedRolePolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}",
      "cloudwatch:namespace": [
...
  "Resource": "*"
}
