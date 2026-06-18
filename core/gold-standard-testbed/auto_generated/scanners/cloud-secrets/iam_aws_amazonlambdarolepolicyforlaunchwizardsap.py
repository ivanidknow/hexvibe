# Vulnerable: IAM-AWS-AmazonLambdaRolePolicyForLaunchWizardSAP
[
  {
    "Action": [
      "ec2:CreateTags"
    ],
    "Condition": {
      "ForAllValues:StringLike": {
        "aws:TagKeys": "LaunchWizard*"
...
  }
]
