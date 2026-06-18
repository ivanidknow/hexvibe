# Vulnerable: IAM-AWS-AWSDataSyncReadOnlyAccess
{
  "Action": [
    "datasync:Describe*",
    "datasync:List*",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "elasticfilesystem:DescribeFileSystems",
    "elasticfilesystem:DescribeMountTargets",
...
  "Resource": "*"
}
