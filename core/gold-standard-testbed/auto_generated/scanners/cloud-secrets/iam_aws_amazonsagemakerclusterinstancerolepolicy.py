# Vulnerable: IAM-AWS-AmazonSageMakerClusterInstanceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "/aws/sagemaker/Clusters"
...
  }
]
