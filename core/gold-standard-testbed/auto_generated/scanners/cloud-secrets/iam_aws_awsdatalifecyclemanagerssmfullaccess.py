# Vulnerable: IAM-AWS-AWSDataLifecycleManagerSSMFullAccess
{
  "Action": [
    "ssm:GetCommandInvocation",
    "ssm:ListCommands",
    "ssm:DescribeInstanceInformation"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "AllowSSMReadOnlyAccess"
}
