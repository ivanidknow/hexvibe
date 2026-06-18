# Vulnerable: IAM-AWS-AWSLakeFormationDataAdmin
{
  "Action": [
    "lakeformation:*",
    "cloudtrail:DescribeTrails",
    "cloudtrail:LookupEvents",
    "glue:CreateCatalog",
    "glue:UpdateCatalog",
    "glue:DeleteCatalog",
...
  "Sid": "AWSLakeFormationDataAdminAllow"
}
