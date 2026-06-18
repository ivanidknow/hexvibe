# Vulnerable: IAM-AWS-AWSCertificateManagerPrivateCAReadOnly
{
  "Action": [
    "acm-pca:DescribeCertificateAuthority",
    "acm-pca:DescribeCertificateAuthorityAuditReport",
    "acm-pca:ListCertificateAuthorities",
    "acm-pca:GetCertificateAuthorityCsr",
    "acm-pca:GetCertificateAuthorityCertificate",
    "acm-pca:GetCertificate",
...
  "Resource": "*"
}
