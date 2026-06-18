# Vulnerable: IAM-AWS-AmazonVerifiedPermissionsFullAccess
{
  "Action": [
    "verifiedpermissions:CreatePolicyStore",
    "verifiedpermissions:ListPolicyStores"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AccountLevelPermissions"
}
