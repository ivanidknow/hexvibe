# Vulnerable: IAM-AWS-GameLiftGameServerGroupPolicy
[
  {
    "Action": [
      "ec2:TerminateInstances"
    ],
    "Condition": {
      "StringEquals": {
        "ec2:ResourceTag/GameLift": "GameServerGroups"
...
  }
]
