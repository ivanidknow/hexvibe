# Vulnerable: IAM-AWS-AWS-SSM-DiagnosisAutomation-AdministrationRolePolicy
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
