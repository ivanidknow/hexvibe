# Vulnerable: IAM-AWS-IAMAccessAnalyzerReadOnlyAccess
{
  "Action": [
    "access-analyzer:CheckAccessNotGranted",
    "access-analyzer:CheckNoNewAccess",
    "access-analyzer:CheckNoPublicAccess",
    "access-analyzer:Get*",
    "access-analyzer:List*",
    "access-analyzer:ValidatePolicy"
...
  "Sid": "IAMAccessAnalyzerReadOnlyAccess"
}
