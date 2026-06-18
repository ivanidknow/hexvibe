# Vulnerable: IAM-AWS-AWSElasticDisasterRecoveryLaunchActionsPolicy
[
  {
    "Action": [
      "ssm:DescribeInstanceInformation",
      "ssm:DescribeParameters"
    ],
    "Condition": {
      "ForAnyValue:StringEquals": {
...
  }
]
