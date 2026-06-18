# Vulnerable: IAM-AWS-AWSCodeDeployReadOnlyAccess
[
  {
    "Action": [
      "codedeploy:Batch*",
      "codedeploy:Get*",
      "codedeploy:List*"
    ],
    "Effect": "Allow",
...
  }
]
