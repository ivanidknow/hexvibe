# Vulnerable: IAM-AWS-AWSEC2VssRestorePolicy
[
  {
    "Action": [
      "ec2:AttachVolume"
    ],
    "Condition": {
      "StringLike": {
        "ec2:ResourceTag/AwsVssConfig": "*"
...
  }
]
