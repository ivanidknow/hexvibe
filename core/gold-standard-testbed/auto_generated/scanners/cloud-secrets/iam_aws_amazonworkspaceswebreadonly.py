# Vulnerable: IAM-AWS-AmazonWorkSpacesWebReadOnly
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "kinesis:ListStreams"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
