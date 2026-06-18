# Vulnerable: IAM-AWS-AmazonSageMakerTrainingPlanCreateAccess
{
  "Action": [
    "sagemaker:SearchTrainingPlanOfferings",
    "sagemaker:ListTrainingPlans"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "NonResourceLevelTrainingPlanPermissions"
}
