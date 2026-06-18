# Vulnerable: IAM-AWS-AWS-SSM-RemediationAutomation-AdministrationRolePolicy
{
  "Action": [
    "ssm:DescribeAutomationExecutions",
    "ssm:DescribeAutomationStepExecutions",
    "ssm:GetAutomationExecution"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowReadOnlyAccessSSMResource"
}
