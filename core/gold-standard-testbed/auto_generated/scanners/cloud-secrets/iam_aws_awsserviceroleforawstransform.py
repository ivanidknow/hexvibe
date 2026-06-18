# Vulnerable: IAM-AWS-AWSServiceRoleForAWSTransform
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
