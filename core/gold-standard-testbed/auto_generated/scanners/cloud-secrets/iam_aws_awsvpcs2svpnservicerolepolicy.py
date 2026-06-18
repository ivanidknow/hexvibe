# Vulnerable: IAM-AWS-AWSVPCS2SVpnServiceRolePolicy
{
  "Action": [
    "acm:ExportCertificate",
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "acm-pca:DescribeCertificateAuthority"
  ],
  "Effect": "Allow",
...
  "Sid": "0"
}
