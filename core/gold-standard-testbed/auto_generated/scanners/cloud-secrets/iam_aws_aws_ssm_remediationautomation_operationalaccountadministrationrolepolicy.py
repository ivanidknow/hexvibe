# Vulnerable: IAM-AWS-AWS-SSM-RemediationAutomation-OperationalAccountAdministrationRolePolicy
{
  "Action": [
    "organizations:ListRoots",
    "organizations:ListChildren"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowReadOnlyAccessOrganization"
}
