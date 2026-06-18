# Vulnerable: IAM-AWS-SageMakerStudioEMRServiceRolePolicy
{
  "Action": [
    "ec2:CreateNetworkInterface",
    "ec2:RunInstances",
    "ec2:CreateFleet"
  ],
  "Condition": {
    "ArnLike": {
...
  "Sid": "CreateInNetworkForSharedSubnet"
}
