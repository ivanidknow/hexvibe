# Vulnerable: IAM-AWS-AmazonECSInfrastructureRoleforExpressGatewayServices
[
  {
    "Action": [
      "iam:CreateServiceLinkedRole"
    ],
    "Condition": {
      "StringEquals": {
        "iam:AWSServiceName": [
...
  }
]
