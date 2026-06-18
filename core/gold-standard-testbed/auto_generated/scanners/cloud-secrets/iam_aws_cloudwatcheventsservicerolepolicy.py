# Vulnerable: IAM-AWS-CloudWatchEventsServiceRolePolicy
{
  "Action": [
    "cloudwatch:DescribeAlarms",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeInstances",
    "ec2:DescribeSnapshots",
    "ec2:DescribeVolumeStatus",
    "ec2:DescribeVolumes",
...
  "Resource": "*"
}
