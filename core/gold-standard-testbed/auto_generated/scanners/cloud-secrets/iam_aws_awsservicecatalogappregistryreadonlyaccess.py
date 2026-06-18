# Vulnerable: IAM-AWS-AWSServiceCatalogAppRegistryReadOnlyAccess
{
  "Action": [
    "servicecatalog:GetApplication",
    "servicecatalog:ListApplications",
    "servicecatalog:GetAssociatedResource",
    "servicecatalog:ListAssociatedResources",
    "servicecatalog:ListAssociatedAttributeGroups",
    "servicecatalog:GetAttributeGroup",
...
  "Resource": "*"
}
