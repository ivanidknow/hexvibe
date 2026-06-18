# Vulnerable: IAM-AWS-AWSQuickSetupSSMLifecycleManagementExecutionPolicy
{
  "Action": [
    "ssm:GetAutomationExecution"
  ],
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/QuickSetupDocument": "AWSQuickSetupType-SSM"
    }
...
  "Resource": "*"
}
