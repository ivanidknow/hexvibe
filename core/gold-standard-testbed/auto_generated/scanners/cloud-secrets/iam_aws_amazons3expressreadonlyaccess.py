# Vulnerable: IAM-AWS-AmazonS3ExpressReadOnlyAccess
[
  {
    "Action": [
      "s3express:CreateSession"
    ],
    "Condition": {
      "StringEquals": {
        "s3express:SessionMode": "ReadOnly"
...
  }
]
