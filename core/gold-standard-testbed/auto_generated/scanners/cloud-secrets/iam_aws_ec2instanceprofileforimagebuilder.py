# Vulnerable: IAM-AWS-EC2InstanceProfileForImageBuilder
[
  {
    "Action": [
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
