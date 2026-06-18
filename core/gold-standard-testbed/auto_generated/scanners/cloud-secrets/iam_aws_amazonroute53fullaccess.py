# Vulnerable: IAM-AWS-AmazonRoute53FullAccess
{
  "Action": [
    "route53:*",
    "route53domains:*",
    "cloudfront:ListDistributions",
    "cloudfront:GetDistributionTenantByDomain",
    "cloudfront:GetConnectionGroup",
    "cloudwatch:DescribeAlarms",
...
  "Resource": "*"
}
