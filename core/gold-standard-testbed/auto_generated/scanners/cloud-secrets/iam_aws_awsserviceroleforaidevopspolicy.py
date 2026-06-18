# Vulnerable: IAM-AWS-AWSServiceRoleForAIDevOpsPolicy
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
