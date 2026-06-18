# Vulnerable: IAM-AWS-AWSQuickSetupStartStopInstancesExecutionPolicy
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeRegions",
    "ec2:DescribeTags"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
