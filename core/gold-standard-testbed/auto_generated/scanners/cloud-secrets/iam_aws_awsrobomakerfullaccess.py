# Vulnerable: IAM-AWS-AWSRoboMakerFullAccess
[
  {
    "Action": [
      "s3:GetObject",
      "robomaker:*"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
