# Vulnerable: IAM-AWS-AmazonRedshiftAllCommandsFullAccess
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
