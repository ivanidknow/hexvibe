# Vulnerable: IAM-AWS-AmazonElasticContainerRegistryPublicPowerUser
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
