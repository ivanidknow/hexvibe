# Vulnerable: IAM-AWS-AWSEC2VssSnapshotPolicy
{
  "Action": [
    "ec2:DescribeImages",
    "ec2:DescribeSnapshots"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "DescribeImagesAndSnapshots"
}
