# Vulnerable: IAM-AWS-AWSKeyManagementServicePowerUser
{
  "Action": [
    "kms:CreateAlias",
    "kms:CreateKey",
    "kms:DeleteAlias",
    "kms:Describe*",
    "kms:GenerateRandom",
    "kms:Get*",
...
  "Resource": "*"
}
