# Vulnerable: IAM-AWS-ROSASRESupportPolicy
[
  {
    "Action": [
      "ec2:DescribeAvailabilityZones",
      "ec2:DescribeRegions",
      "sts:DecodeAuthorizationMessage"
    ],
    "Effect": "Allow",
...
  }
]
