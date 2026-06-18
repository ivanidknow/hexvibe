# Vulnerable: IAM-AWS-AmazonEC2ReadOnlyAccess
[
  {
    "Action": [
      "ec2:Describe*",
      "ec2:GetSecurityGroupsForVpc"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
