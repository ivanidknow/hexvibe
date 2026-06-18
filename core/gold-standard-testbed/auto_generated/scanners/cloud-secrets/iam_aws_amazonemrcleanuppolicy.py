# Vulnerable: IAM-AWS-AmazonEMRCleanupPolicy
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeLaunchTemplates",
    "ec2:DescribeSpotInstanceRequests",
    "ec2:DeleteLaunchTemplate",
    "ec2:ModifyInstanceAttribute",
    "ec2:TerminateInstances",
...
  "Resource": "*"
}
