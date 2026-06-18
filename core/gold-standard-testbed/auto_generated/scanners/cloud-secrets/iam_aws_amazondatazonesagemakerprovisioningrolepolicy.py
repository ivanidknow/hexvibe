# Vulnerable: IAM-AWS-AmazonDataZoneSageMakerProvisioningRolePolicy
[
  {
    "Action": [
      "sagemaker:CreateDomain"
    ],
    "Condition": {
      "ForAnyValue:StringEquals": {
        "aws:TagKeys": [
...
  }
]
