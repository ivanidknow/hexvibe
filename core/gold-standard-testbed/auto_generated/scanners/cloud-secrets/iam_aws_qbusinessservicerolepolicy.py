# Vulnerable: IAM-AWS-QBusinessServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/QBusiness"
...
  }
]
