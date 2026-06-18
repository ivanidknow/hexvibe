# Vulnerable: IAM-AWS-AWSECRPullThroughCacheServiceRolePolicy
{
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload",
    "ecr:PutImage"
...
  "Resource": "*"
}
