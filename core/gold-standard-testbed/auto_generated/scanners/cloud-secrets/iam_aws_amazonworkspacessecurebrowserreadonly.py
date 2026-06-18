# Vulnerable: IAM-AWS-AmazonWorkSpacesSecureBrowserReadOnly
{
  "Action": [
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeSecurityGroups",
    "kinesis:ListStreams"
  ],
  "Effect": "Allow",
...
  "Sid": "Dependencies"
}
