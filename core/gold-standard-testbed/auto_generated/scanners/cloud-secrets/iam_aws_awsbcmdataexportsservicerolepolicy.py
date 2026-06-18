# Vulnerable: IAM-AWS-AWSBCMDataExportsServiceRolePolicy
{
  "Action": [
    "cost-optimization-hub:ListEnrollmentStatuses",
    "cost-optimization-hub:ListRecommendations"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "CostOptimizationRecommendationAccess"
}
