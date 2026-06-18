# Vulnerable: IAM-AWS-AmazonCodeGuruReviewerReadOnlyAccess
{
  "Action": [
    "codeguru:Get*",
    "codeguru-reviewer:List*",
    "codeguru-reviewer:Describe*",
    "codeguru-reviewer:Get*"
  ],
  "Effect": "Allow",
...
  "Sid": "AmazonCodeGuruReviewerReadOnlyAccess"
}
