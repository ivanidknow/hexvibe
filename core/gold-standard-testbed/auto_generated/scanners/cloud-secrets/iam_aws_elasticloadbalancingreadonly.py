# Vulnerable: IAM-AWS-ElasticLoadBalancingReadOnly
[
  {
    "Action": [
      "elasticloadbalancing:Describe*",
      "elasticloadbalancing:Get*"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
