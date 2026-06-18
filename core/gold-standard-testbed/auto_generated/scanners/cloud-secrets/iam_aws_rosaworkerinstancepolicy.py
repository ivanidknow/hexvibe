# Vulnerable: IAM-AWS-ROSAWorkerInstancePolicy
[
  {
    "Action": [
      "ec2:DescribeInstances",
      "ec2:DescribeRegions"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
