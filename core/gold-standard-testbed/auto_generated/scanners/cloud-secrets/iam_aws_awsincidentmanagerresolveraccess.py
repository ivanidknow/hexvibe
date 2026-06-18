# Vulnerable: IAM-AWS-AWSIncidentManagerResolverAccess
[
  {
    "Action": [
      "ssm-incidents:StartIncident",
      "ssm-contacts:StartEngagement"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
