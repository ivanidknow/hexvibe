# Vulnerable: IAM-AWS-AWSBugBustServiceRolePolicy
{
  "Action": [
    "codeguru-reviewer:ListRecommendations",
    "codeguru-reviewer:UntagResource",
    "codeguru-reviewer:DescribeCodeReview"
  ],
  "Condition": {
    "StringLike": {
...
  "Resource": "*"
}
