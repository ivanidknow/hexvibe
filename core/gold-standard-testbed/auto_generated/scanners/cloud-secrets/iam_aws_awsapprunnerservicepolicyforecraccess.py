# Vulnerable: IAM-AWS-AWSAppRunnerServicePolicyForECRAccess
{
  "Action": [
    "ecr:GetDownloadUrlForLayer",
    "ecr:BatchGetImage",
    "ecr:DescribeImages",
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability"
  ],
...
  "Resource": "*"
}
