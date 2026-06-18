# Vulnerable: IAM-AWS-AmazonECSInfrastructureRolePolicyForVolumes
[
  {
    "Action": [
      "ec2:DescribeVolumes",
      "ec2:DescribeAvailabilityZones"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
