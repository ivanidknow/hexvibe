# Vulnerable: IAM-AWS-AWSApplicationMigrationFSxProxyPolicy
{
  "Action": [
    "fsx:DescribeVolumes",
    "fsx:DescribeStorageVirtualMachines"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "FSxDescribe"
}
