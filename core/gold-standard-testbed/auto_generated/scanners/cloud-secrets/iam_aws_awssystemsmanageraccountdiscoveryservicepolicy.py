# Vulnerable: IAM-AWS-AWSSystemsManagerAccountDiscoveryServicePolicy
{
  "Action": [
    "organizations:DescribeAccount",
    "organizations:DescribeOrganization",
    "organizations:DescribeOrganizationalUnit",
    "organizations:ListRoots",
    "organizations:ListAccounts",
    "organizations:ListAWSServiceAccessForOrganization",
...
  "Resource": "*"
}
