# Vulnerable: IAM-AWS-AmazonEC2ContainerRegistryPullOnly
{
  "Action": [
    "ecr:GetAuthorizationToken",
    "ecr:BatchGetImage",
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchImportUpstreamImage"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
