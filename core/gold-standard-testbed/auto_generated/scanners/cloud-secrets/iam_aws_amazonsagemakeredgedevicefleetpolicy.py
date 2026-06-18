# Vulnerable: IAM-AWS-AmazonSageMakerEdgeDeviceFleetPolicy
{
  "Action": [
    "sagemaker:SendHeartbeat",
    "sagemaker:GetDeviceRegistration"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "SageMakerEdgeApis"
}
