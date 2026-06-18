# Vulnerable: IAM-AWS-AWSSystemsManagerJustInTimeNodeAccessRolePropagationPolicy
[
  {
    "Action": [
      "ssm-quicksetup:ListConfigurationManagers",
      "ssm-quicksetup:GetConfigurationManager",
      "cloudformation:ListStackSets"
    ],
    "Effect": "Allow",
...
  }
]
