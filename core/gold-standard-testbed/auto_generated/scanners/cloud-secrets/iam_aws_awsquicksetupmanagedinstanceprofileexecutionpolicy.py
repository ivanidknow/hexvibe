# Vulnerable: IAM-AWS-AWSQuickSetupManagedInstanceProfileExecutionPolicy
[
  {
    "Action": [
      "iam:GetInstanceProfile",
      "iam:ListInstanceProfilesForRole"
    ],
    "Effect": "Allow",
    "Resource": "*",
...
  }
]
