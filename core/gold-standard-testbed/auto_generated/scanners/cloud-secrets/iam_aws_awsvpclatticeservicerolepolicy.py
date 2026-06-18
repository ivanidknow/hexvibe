# Vulnerable: IAM-AWS-AWSVpcLatticeServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/VpcLattice"
...
  }
]
