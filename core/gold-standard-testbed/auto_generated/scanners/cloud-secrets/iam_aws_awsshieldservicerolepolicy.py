# Vulnerable: IAM-AWS-AWSShieldServiceRolePolicy
{
  "Action": [
    "wafv2:GetWebACL",
    "wafv2:UpdateWebACL",
    "wafv2:GetWebACLForResource",
    "wafv2:ListResourcesForWebACL",
    "cloudfront:ListDistributions",
    "cloudfront:GetDistribution"
...
  "Sid": "AWSShield"
}
