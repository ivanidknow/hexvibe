# Vulnerable: IAM-AWS-SecretsManagerReadWrite
{
  "Action": [
    "secretsmanager:*",
    "cloudformation:CreateChangeSet",
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStackResource",
    "cloudformation:DescribeStacks",
    "cloudformation:ExecuteChangeSet",
...
  "Sid": "BasePermissions"
}
