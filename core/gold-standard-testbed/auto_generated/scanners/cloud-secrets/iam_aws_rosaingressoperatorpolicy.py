# Vulnerable: IAM-AWS-ROSAIngressOperatorPolicy
[
  {
    "Action": [
      "elasticloadbalancing:DescribeLoadBalancers",
      "route53:ListHostedZones",
      "tag:GetResources"
    ],
    "Effect": "Allow",
...
  }
]
