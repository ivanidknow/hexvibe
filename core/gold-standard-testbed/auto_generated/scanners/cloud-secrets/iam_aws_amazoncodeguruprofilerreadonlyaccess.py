# Vulnerable: IAM-AWS-AmazonCodeGuruProfilerReadOnlyAccess
{
  "Action": [
    "codeguru:Get*",
    "codeguru-profiler:BatchGet*",
    "codeguru-profiler:Describe*",
    "codeguru-profiler:Get*",
    "codeguru-profiler:List*",
    "iam:ListRoles",
...
  "Resource": "*"
}
