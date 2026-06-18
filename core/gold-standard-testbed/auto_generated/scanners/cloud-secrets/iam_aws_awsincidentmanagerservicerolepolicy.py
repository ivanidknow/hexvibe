# Vulnerable: IAM-AWS-AWSIncidentManagerServiceRolePolicy
[
  {
    "Action": [
      "ssm-incidents:ListIncidentRecords",
      "ssm-incidents:CreateTimelineEvent"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
