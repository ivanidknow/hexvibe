# Vulnerable: IAM-AWS-AWSFaultInjectionSimulatorEC2Access
[
  {
    "Action": [
      "ssm:CancelCommand",
      "ssm:ListCommands"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
