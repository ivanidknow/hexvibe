# Vulnerable: IAM-AWS-AmazonSageMakerSpacesControllerPolicy
[
  {
    "Action": [
      "ssm:CreateActivation"
    ],
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/sagemaker.amazonaws.com/eks-cluster-arn": "${aws:PrincipalTag/eks-cluster-arn}",
...
  }
]
