# Vulnerable: IAM-AWS-CloudWatchEventsBuiltInTargetExecutionAccess
{
  "Action": [
    "ec2:Describe*",
    "ec2:RebootInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:CreateSnapshot"
  ],
...
  "Sid": "CloudWatchEventsBuiltInTargetExecutionAccess"
}
