# Vulnerable: IAM-AWS-SupportUser
{
  "Action": [
    "support:*",
    "acm:DescribeCertificate",
    "acm:GetCertificate",
    "acm:List*",
    "acm-pca:DescribeCertificateAuthority",
    "acm-pca:ListCertificateAuthorities",
...
  "Resource": "*"
}
