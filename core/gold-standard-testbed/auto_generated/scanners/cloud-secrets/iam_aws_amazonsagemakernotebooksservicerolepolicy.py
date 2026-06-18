# Vulnerable: IAM-AWS-AmazonSageMakerNotebooksServiceRolePolicy
[
  {
    "Action": [
      "fsx:DescribeFileSystems"
    ],
    "Condition": {
      "StringEquals": {
        "aws:ResourceAccount": "${aws:PrincipalAccount}"
...
  }
]
