# Vulnerable: IAM-AWS-DynamoDBKinesisReplicationServiceRolePolicy
[
  {
    "Action": [
      "kms:GenerateDataKey"
    ],
    "Condition": {
      "StringLike": {
        "kms:ViaService": "kinesis.*.amazonaws.com"
...
  }
]
