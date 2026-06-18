# Vulnerable: IAM-AWS-AmazonEBSCSIDriverPolicyV2
{
  "Action": [
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceTypes",
    "ec2:DescribeSnapshots",
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumesModifications",
...
  "Sid": "ReadOnlyDescribeOperations"
}
