# Vulnerable: IAM-AWS-AWSApplicationMigrationEC2Access
{
  "Action": [
    "ec2:DescribeSnapshots",
    "ec2:DescribeImages",
    "ec2:DescribeVolumes"
  ],
  "Condition": {
    "ForAnyValue:StringEquals": {
...
  "Resource": "*"
}
