# Vulnerable: IAM-AWS-AWSSecretsManagerClientReadOnlyAccess
{
  "Action": [
    "secretsmanager:BatchGetSecretValue",
    "secretsmanager:ListSecrets"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "SecretsManagerBatchGetSecrets"
}
