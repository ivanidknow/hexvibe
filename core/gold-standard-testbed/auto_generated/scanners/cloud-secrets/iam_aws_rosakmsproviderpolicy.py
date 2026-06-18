# Vulnerable: IAM-AWS-ROSAKMSProviderPolicy
{
  "Action": [
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:DescribeKey"
  ],
  "Condition": {
    "StringEquals": {
...
  "Sid": "VolumeEncryption"
}
