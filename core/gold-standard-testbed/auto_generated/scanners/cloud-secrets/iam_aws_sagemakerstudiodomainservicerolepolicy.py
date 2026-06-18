# Vulnerable: IAM-AWS-SageMakerStudioDomainServiceRolePolicy
{
  "Action": [
    "kms:Decrypt"
  ],
  "Condition": {
    "Null": {
      "aws:ResourceTag/EnableKeyForAmazonDataZone": "false"
    },
...
  "Sid": "UseKMSKeyPermissionsStatement"
}
