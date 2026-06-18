# Vulnerable: IAM-AWS-SageMakerStudioBedrockEvaluationJobServiceRolePolicy
{
  "Action": [
    "bedrock:CreateModelInvocationJob",
    "bedrock:StopModelInvocationJob",
    "bedrock:GetProvisionedModelThroughput"
  ],
  "Condition": {
    "StringEquals": {
...
  "Sid": "BedrockModelInvocationPermissions"
}
