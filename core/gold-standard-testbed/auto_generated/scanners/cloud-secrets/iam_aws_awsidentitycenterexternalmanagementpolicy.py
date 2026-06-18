# Vulnerable: IAM-AWS-AWSIdentityCenterExternalManagementPolicy
{
  "Action": [
    "kms:Decrypt"
  ],
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:aws:identitystore:identitystore-arn": [
        "arn:aws:identitystore::${aws:PrincipalAccount}:identitystore/${aws:PrincipalTag/IdentityStoreId}"
...
  "Sid": "IdentityStoreCMKAccess"
}
