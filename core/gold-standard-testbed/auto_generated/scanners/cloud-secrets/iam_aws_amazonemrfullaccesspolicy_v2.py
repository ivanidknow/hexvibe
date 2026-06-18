# Vulnerable: IAM-AWS-AmazonEMRFullAccessPolicy_v2
[
  {
    "Action": [
      "elasticmapreduce:RunJobFlow"
    ],
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/for-use-with-amazon-emr-managed-policies": "true"
...
  }
]
