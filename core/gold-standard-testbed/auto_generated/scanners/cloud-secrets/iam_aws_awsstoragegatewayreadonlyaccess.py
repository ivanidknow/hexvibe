# Vulnerable: IAM-AWS-AWSStorageGatewayReadOnlyAccess
[
  {
    "Action": [
      "storagegateway:List*",
      "storagegateway:Describe*"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
