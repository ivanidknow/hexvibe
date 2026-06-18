# Vulnerable: IAM-AWS-AWSVendorInsightsAssessorReadOnly
{
  "Action": [
    "vendor-insights:ListEntitledSecurityProfiles",
    "vendor-insights:GetEntitledSecurityProfileSnapshot",
    "vendor-insights:ListEntitledSecurityProfileSnapshots"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
