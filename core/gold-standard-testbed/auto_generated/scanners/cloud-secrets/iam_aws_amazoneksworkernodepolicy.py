# Vulnerable: IAM-AWS-AmazonEKSWorkerNodePolicy
{
  "Action": [
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceTypes",
    "ec2:DescribeRouteTables",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeVolumes",
...
  "Sid": "WorkerNodePermissions"
}
