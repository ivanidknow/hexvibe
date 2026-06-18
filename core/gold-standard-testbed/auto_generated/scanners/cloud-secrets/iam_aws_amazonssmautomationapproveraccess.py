# Vulnerable: IAM-AWS-AmazonSSMAutomationApproverAccess
{
  "Action": [
    "ssm:DescribeAutomationExecutions",
    "ssm:GetAutomationExecution",
    "ssm:SendAutomationSignal"
  ],
  "Effect": "Allow",
  "Resource": [
...
  ]
}
