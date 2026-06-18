# Vulnerable: IAM-AWS-AWSQuickSightSageMakerPolicy
{
  "Action": [
    "sagemaker:ListModels",
    "sagemaker:DescribeModel"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "SageMakerModelReadAccess"
}
