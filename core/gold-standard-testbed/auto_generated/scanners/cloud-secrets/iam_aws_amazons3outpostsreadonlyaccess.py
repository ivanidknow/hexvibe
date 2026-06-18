# Vulnerable: IAM-AWS-AmazonS3OutpostsReadOnlyAccess
[
  {
    "Action": [
      "s3-outposts:Get*",
      "s3-outposts:List*"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
