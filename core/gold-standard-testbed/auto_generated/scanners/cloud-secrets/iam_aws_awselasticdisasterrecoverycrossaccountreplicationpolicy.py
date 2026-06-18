# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryCrossAccountReplicationPolicy
{
  "Action": [
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumeAttribute",
    "ec2:DescribeInstances",
    "drs:DescribeSourceServers",
    "drs:DescribeReplicationConfigurationTemplates",
    "drs:CreateSourceServerForDrs"
...
  "Sid": "CrossAccountPolicy1"
}
