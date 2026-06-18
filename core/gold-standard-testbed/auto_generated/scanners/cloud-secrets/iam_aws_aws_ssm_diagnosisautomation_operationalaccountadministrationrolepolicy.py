# Vulnerable: IAM-AWS-AWS-SSM-DiagnosisAutomation-OperationalAccountAdministrationRolePolicy
{
  "Action": [
    "organizations:ListRoots",
    "organizations:ListChildren"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowReadOnlyAccessOrganization"
}
