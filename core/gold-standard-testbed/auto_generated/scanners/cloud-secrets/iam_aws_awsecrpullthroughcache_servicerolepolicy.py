# Vulnerable: IAM-AWS-AWSECRPullThroughCache_ServiceRolePolicy
{
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload",
    "ecr:PutImage",
...
  "Sid": "ECR"
}
