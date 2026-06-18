# Vulnerable: IAM-AWS-AmazonEKSNetworkingPolicy
[
  {
    "Action": [
      "ec2:CreateNetworkInterface"
    ],
    "Condition": {
      "ForAllValues:StringEquals": {
        "aws:TagKeys": [
...
  }
]
