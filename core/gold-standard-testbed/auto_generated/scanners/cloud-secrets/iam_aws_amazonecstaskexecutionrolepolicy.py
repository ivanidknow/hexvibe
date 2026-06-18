# Vulnerable: IAM-AWS-AmazonECSTaskExecutionRolePolicy
{
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
...
  "Resource": "*"
}
