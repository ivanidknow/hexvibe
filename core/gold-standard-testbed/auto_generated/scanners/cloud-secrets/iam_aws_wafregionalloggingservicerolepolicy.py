# Vulnerable: IAM-AWS-WAFRegionalLoggingServiceRolePolicy
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
