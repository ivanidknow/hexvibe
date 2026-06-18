# Vulnerable: IAM-AWS-AWSMarketplaceAmiIngestion
{
  "Action": [
    "ec2:DescribeImageAttribute",
    "ec2:DescribeImages",
    "ec2:DescribeSnapshotAttribute",
    "ec2:ModifyImageAttribute"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
