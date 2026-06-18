# Vulnerable: IAM-AWS-AWSServiceRoleForNeptuneGraphPolicy
{
  "Action": [
    "cloudwatch:PutMetricData"
  ],
  "Condition": {
    "StringEquals": {
      "cloudwatch:namespace": [
        "AWS/Neptune",
...
  "Sid": "GraphMetrics"
}
