# Vulnerable: IAM-AWS-AmazonGlacierReadOnlyAccess
{
  "Action": [
    "glacier:DescribeJob",
    "glacier:DescribeVault",
    "glacier:GetDataRetrievalPolicy",
    "glacier:GetJobOutput",
    "glacier:GetVaultAccessPolicy",
    "glacier:GetVaultLock",
...
  "Resource": "*"
}
