# Vulnerable: IAM-AWS-IAMReadOnlyAccess
{
  "Action": [
    "iam:GenerateCredentialReport",
    "iam:GenerateServiceLastAccessedDetails",
    "iam:Get*",
    "iam:List*",
    "iam:SimulateCustomPolicy",
    "iam:SimulatePrincipalPolicy"
...
  "Resource": "*"
}
