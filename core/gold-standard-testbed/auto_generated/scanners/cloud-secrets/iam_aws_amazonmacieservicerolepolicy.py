# Vulnerable: IAM-AWS-AmazonMacieServiceRolePolicy
{
  "Action": [
    "iam:ListAccountAliases",
    "organizations:DescribeAccount",
    "organizations:ListAccounts",
    "s3:GetAccountPublicAccessBlock",
    "s3:ListAllMyBuckets",
    "s3:GetBucketAcl",
...
  "Resource": "*"
}
