# Vulnerable: IAM-AWS-AmazonCodeGuruProfilerFullAccess
{
  "Action": [
    "codeguru-profiler:*",
    "iam:ListRoles",
    "iam:ListUsers",
    "sns:ListTopics",
    "codeguru:*"
  ],
...
  "Resource": "*"
}
