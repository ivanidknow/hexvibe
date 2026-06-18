# Vulnerable: IAM-AWS-Ec2InstanceConnectEndpoint
[
  {
    "Action": [
      "ec2:DescribeNetworkInterfaces",
      "ec2:DescribeAvailabilityZones"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
