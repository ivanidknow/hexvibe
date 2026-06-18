# Vulnerable: IAM-AWS-AmazonChimeSDKMediaPipelinesServiceLinkedRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/ChimeSDK"
...
  }
]
