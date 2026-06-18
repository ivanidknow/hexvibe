# Vulnerable: IAM-AWS-AWSAppMeshReadOnly
[
  {
    "Action": [
      "appmesh:Describe*",
      "appmesh:List*"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
