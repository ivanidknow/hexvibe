# Vulnerable: IAM-AWS-CustomerProfilesServiceLinkedRolePolicy
[
  {
    "Action": [
      "cloudwatch:PutMetricData"
    ],
    "Condition": {
      "StringEquals": {
        "cloudwatch:namespace": "AWS/CustomerProfiles"
...
  }
]
