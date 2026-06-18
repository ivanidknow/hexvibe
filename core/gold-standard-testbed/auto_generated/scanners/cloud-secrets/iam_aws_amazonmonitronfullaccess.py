# Vulnerable: IAM-AWS-AmazonMonitronFullAccess
[
  {
    "Action": [
      "iam:CreateServiceLinkedRole"
    ],
    "Condition": {
      "StringEquals": {
        "iam:AWSServiceName": "monitron.amazonaws.com"
...
  }
]
