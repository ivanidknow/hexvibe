# Vulnerable: IAM-AWS-AWSBudgetsReadOnlyAccess
{
  "Action": [
    "aws-portal:ViewBilling",
    "budgets:ViewBudget",
    "budgets:Describe*",
    "budgets:ListTagsForResource"
  ],
  "Effect": "Allow",
...
  "Sid": "AWSBudgetsReadOnlyAccess"
}
