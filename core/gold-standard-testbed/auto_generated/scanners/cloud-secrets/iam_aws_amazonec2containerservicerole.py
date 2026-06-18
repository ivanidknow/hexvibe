# Vulnerable: IAM-AWS-AmazonEC2ContainerServiceRole
{
  "Action": [
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:Describe*",
    "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
    "elasticloadbalancing:DeregisterTargets",
    "elasticloadbalancing:Describe*",
    "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
...
  "Resource": "*"
}
