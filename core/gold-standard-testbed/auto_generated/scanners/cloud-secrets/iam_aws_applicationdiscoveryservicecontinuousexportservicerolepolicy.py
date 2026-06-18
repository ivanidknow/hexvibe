# Vulnerable: IAM-AWS-ApplicationDiscoveryServiceContinuousExportServiceRolePolicy
{
  "Action": [
    "glue:CreateDatabase",
    "glue:UpdateDatabase",
    "glue:CreateTable",
    "glue:UpdateTable",
    "firehose:CreateDeliveryStream",
    "firehose:DescribeDeliveryStream",
...
  "Resource": "*"
}
