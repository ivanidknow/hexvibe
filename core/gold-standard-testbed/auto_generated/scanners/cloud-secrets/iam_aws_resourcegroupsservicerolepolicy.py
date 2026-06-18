# Vulnerable: IAM-AWS-ResourceGroupsServiceRolePolicy
{
  "Action": [
    "tag:GetResources",
    "cloudformation:DescribeStacks",
    "cloudformation:ListStackResources"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
