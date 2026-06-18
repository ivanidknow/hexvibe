# Vulnerable: IAM-AWS-MultiPartyApprovalReadOnlyAccess
[
  {
    "Action": [
      "mpa:Get*",
      "mpa:List*"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
