# Vulnerable: IAM-AWS-AmazonChimeSDKMessagingServiceRolePolicy
{
  "Action": [
    "kms:GenerateDataKey"
  ],
  "Condition": {
    "StringLike": {
      "kms:ViaService": [
        "kinesis.*.amazonaws.com"
...
  "Resource": "*"
}
