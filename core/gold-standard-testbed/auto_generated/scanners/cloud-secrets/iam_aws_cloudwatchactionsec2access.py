# Vulnerable: IAM-AWS-CloudWatchActionsEC2Access
{
  "Action": [
    "cloudwatch:Describe*",
    "ec2:Describe*",
    "ec2:RebootInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances"
  ],
...
  "Resource": "*"
}
