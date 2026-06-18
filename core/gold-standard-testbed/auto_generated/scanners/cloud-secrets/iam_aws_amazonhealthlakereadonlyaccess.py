# Vulnerable: IAM-AWS-AmazonHealthLakeReadOnlyAccess
{
  "Action": [
    "healthlake:ListFHIRDatastores",
    "healthlake:DescribeFHIRDatastore",
    "healthlake:DescribeFHIRImportJob",
    "healthlake:DescribeFHIRExportJob",
    "healthlake:GetCapabilities",
    "healthlake:ReadResource",
...
  "Resource": "*"
}
