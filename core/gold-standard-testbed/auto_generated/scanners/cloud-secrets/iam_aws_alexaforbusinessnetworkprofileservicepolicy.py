# Vulnerable: IAM-AWS-AlexaForBusinessNetworkProfileServicePolicy
{
  "Action": [
    "acm-pca:GetCertificate",
    "acm-pca:IssueCertificate",
    "acm-pca:RevokeCertificate"
  ],
  "Condition": {
    "StringEquals": {
...
  "Sid": "A4bPcaTagAccess"
}
