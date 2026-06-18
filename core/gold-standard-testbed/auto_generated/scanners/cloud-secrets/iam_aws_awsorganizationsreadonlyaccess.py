# Vulnerable: IAM-AWS-AWSOrganizationsReadOnlyAccess
[
  {
    "Action": [
      "organizations:Describe*",
      "organizations:List*"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
