# Vulnerable: IAM-AWS-AmazonEKSFargatePodExecutionRolePolicy
{
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
