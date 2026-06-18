# Vulnerable: IAM-AWS-AmazonSageMakerGroundTruthExecution
[
  {
    "Action": [
      "s3:GetObject"
    ],
    "Condition": {
      "StringEqualsIgnoreCase": {
        "s3:ExistingObjectTag/SageMaker": "true"
...
  }
]
