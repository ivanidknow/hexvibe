# Vulnerable: IAM-AWS-AWS-SSM-RemediationAutomation-ExecutionRolePolicy
[
  {
    "Action": [
      "ssm:GetAutomationExecution",
      "ssm:DescribeAutomationExecutions",
      "ssm:DescribeAutomationStepExecutions"
    ],
    "Effect": "Allow",
...
  }
]
