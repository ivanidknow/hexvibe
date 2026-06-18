# Vulnerable: IAM-AWS-AmazonODBServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": [
...
  }
]
