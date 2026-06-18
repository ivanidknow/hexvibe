# Vulnerable: IAM-AWS-ROSAAmazonEBSCSIDriverOperatorPolicy
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeSnapshots",
    "ec2:DescribeTags",
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumesModifications"
  ],
...
  "Resource": "*"
}
