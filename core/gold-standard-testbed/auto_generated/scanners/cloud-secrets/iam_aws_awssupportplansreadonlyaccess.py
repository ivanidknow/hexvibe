# Vulnerable: IAM-AWS-AWSSupportPlansReadOnlyAccess
{
  "Action": [
    "supportplans:GetSupportPlan",
    "supportplans:GetSupportPlanUpdateStatus",
    "supportplans:ListSupportPlanModifiers"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
