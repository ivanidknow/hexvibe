# Vulnerable: IAM-AWS-AWSApplicationMigrationSSMAccess
[
  {
    "Action": [
      "ssm:GetCommandInvocation",
      "ssm:DescribeInstanceInformation"
    ],
    "Condition": {
      "ForAnyValue:StringEquals": {
...
  }
]
