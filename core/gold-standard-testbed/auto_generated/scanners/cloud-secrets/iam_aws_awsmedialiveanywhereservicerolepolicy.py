# Vulnerable: IAM-AWS-AWSMediaLiveAnywhereServiceRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/MediaLive"
...
  }
]
