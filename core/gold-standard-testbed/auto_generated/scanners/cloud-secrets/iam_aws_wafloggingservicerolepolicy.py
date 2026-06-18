# Vulnerable: IAM-AWS-WAFLoggingServiceRolePolicy
{
  "Action": [
    "kms:GenerateDataKey",
    "kms:Decrypt"
  ],
  "Condition": {
    "StringLike": {
      "kms:ViaService": "firehose.*.amazonaws.com"
...
  "Sid": "KMSForFirehoseSSECMK"
}
