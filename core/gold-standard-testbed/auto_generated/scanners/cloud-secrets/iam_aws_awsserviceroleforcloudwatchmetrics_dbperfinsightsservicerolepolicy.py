# Vulnerable: IAM-AWS-AWSServiceRoleForCloudWatchMetrics_DbPerfInsightsServiceRolePolicy
{
  "Action": [
    "pi:GetResourceMetrics"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "${aws:PrincipalAccount}"
    }
...
  "Resource": "*"
}
