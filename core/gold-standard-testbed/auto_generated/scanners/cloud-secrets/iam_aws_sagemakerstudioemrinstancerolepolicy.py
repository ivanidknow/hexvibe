# Vulnerable: IAM-AWS-SageMakerStudioEMRInstanceRolePolicy
{
  "Action": [
    "sts:AssumeRole",
    "sts:TagSession"
  ],
  "Condition": {
    "ForAllValues:StringEquals": {
      "aws:TagKeys": [
...
  "Sid": "EMRRuntimeRoleAssumePermissions"
}
