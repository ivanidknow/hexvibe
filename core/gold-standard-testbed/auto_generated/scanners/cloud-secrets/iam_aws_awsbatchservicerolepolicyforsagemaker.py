# Vulnerable: IAM-AWS-AWSBatchServiceRolePolicyForSageMaker
[
  {
    "Action": [
      "sagemaker:ListTrainingJobs",
      "sagemaker:Search"
    ],
    "Effect": "Allow",
    "Resource": "*"
...
  }
]
