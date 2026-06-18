# Vulnerable: IAM-AWS-PartnerCentralAccountManagementUserRoleAssociation
{
  "Action": [
    "iam:ListRoles",
    "partnercentral-account-management:AssociatePartnerUser",
    "partnercentral-account-management:DisassociatePartnerUser"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "PartnerUserRoleAssociation"
}
