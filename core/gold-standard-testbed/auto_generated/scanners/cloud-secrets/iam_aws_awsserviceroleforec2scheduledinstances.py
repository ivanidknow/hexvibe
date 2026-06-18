# Vulnerable: IAM-AWS-AWSServiceRoleForEC2ScheduledInstances
{
  "Action": [
    "ec2:TerminateInstances"
  ],
  "Condition": {
    "StringLike": {
      "ec2:ResourceTag/aws:ec2sri:scheduledInstanceId": "*"
    }
...
  "Resource": "*"
}
