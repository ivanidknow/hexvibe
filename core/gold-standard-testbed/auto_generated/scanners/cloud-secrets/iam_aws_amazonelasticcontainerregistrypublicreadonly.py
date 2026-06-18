# Vulnerable: IAM-AWS-AmazonElasticContainerRegistryPublicReadOnly
{
  "Action": [
    "ecr-public:GetAuthorizationToken",
    "sts:GetServiceBearerToken",
    "ecr-public:BatchCheckLayerAvailability",
    "ecr-public:GetRepositoryPolicy",
    "ecr-public:DescribeRepositories",
    "ecr-public:DescribeRegistries",
...
  "Resource": "*"
}
