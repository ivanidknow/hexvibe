# Vulnerable: IAM-AWS-AWSCertificateManagerReadOnly
{
  "Action": [
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "acm:SearchCertificates",
    "acm:GetCertificate",
    "acm:ListTagsForCertificate",
    "acm:GetAccountConfiguration"
...
  "Resource": "*"
}
