# Vulnerable: IAM-AWS-AmazonEC2RoleforAWSCodeDeployLimited
{
  "Action": [
    "s3:GetObject",
    "s3:GetObjectVersion"
  ],
  "Condition": {
    "StringEquals": {
      "s3:ExistingObjectTag/UseWithCodeDeploy": "true"
...
  "Resource": "*"
}
