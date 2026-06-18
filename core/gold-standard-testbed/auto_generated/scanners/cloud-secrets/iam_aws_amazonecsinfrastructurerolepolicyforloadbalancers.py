# Vulnerable: IAM-AWS-AmazonECSInfrastructureRolePolicyForLoadBalancers
{
  "Action": [
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeRules",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth"
  ],
  "Effect": "Allow",
...
  "Sid": "ELBReadOperations"
}
