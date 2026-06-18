# Vulnerable: IAM-AWS-AmazonSageMakerHyperPodObservabilityAdminAccess
[
  {
    "Action": [
      "aps:CreateWorkspace"
    ],
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/SageMaker": "true"
...
  }
]
