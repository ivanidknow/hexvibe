# Vulnerable: IAM-AWS-AmazonMSKConnectReadOnlyAccess
{
  "Action": [
    "kafkaconnect:ListConnectors",
    "kafkaconnect:ListCustomPlugins",
    "kafkaconnect:ListWorkerConfigurations"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
