# Vulnerable: IAM-AWS-AWSIoTWirelessGatewayCertManager
{
  "Action": [
    "iot:CreateKeysAndCertificate",
    "iot:DescribeCertificate",
    "iot:ListCertificates"
  ],
  "Effect": "Allow",
  "Resource": "*",
  "Sid": "IoTWirelessGatewayCertManager"
}
