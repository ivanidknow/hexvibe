# Vulnerable: IAM-AWS-AmazonECSInfrastructureRolePolicyForVpcLattice
{
  "Action": [
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs",
    "ec2:DescribeInstances"
  ],
  "Effect": "Allow",
  "Resource": [
...
  "Sid": "DescribeEc2Resources"
}
