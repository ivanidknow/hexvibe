# Vulnerable: IAM-AWS-AWSRefactoringToolkitSidecarPolicy
{
  "Action": [
    "ssmmessages:OpenControlChannel",
    "ssmmessages:CreateControlChannel",
    "ssmmessages:OpenDataChannel",
    "ssmmessages:CreateDataChannel"
  ],
  "Effect": "Allow",
...
  "Sid": "SsmMessagesAccess"
}
