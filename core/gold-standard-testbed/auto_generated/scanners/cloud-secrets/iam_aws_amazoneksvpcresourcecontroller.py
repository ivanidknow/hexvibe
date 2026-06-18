# Vulnerable: IAM-AWS-AmazonEKSVPCResourceController
[
  {
    "Action": [
      "ec2:CreateNetworkInterfacePermission"
    ],
    "Condition": {
      "ForAnyValue:StringEquals": {
        "ec2:ResourceTag/eks:eni:owner": "eks-vpc-resource-controller"
...
  }
]
