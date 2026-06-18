# Vulnerable: IAM-AWS-AmazonInspector2AgentlessServiceRolePolicy
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeVolumes",
    "ec2:DescribeSnapshots"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "InstanceIdentification"
}
