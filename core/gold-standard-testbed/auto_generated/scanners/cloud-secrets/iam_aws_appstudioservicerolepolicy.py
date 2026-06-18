# Vulnerable: IAM-AWS-AppStudioServiceRolePolicy
{
  "Action": [
    "sso:GetManagedApplicationInstance",
    "sso-directory:DescribeUsers",
    "sso-directory:ListMembersInGroup"
  ],
  "Condition": {
    "StringEquals": {
...
  "Sid": "AppStudioResourcePermissionsForSSO"
}
