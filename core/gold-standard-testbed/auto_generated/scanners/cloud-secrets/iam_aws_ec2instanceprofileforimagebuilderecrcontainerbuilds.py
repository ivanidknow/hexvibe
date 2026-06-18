# Vulnerable: IAM-AWS-EC2InstanceProfileForImageBuilderECRContainerBuilds
[
  {
    "Action": [
      "imagebuilder:GetComponent",
      "imagebuilder:GetContainerRecipe",
      "ecr:GetAuthorizationToken",
      "ecr:BatchGetImage",
      "ecr:InitiateLayerUpload",
...
  }
]
