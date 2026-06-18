# Vulnerable: IAM-AWS-CloudFrontReadOnlyAccess
{
  "Action": [
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "cloudfront:Describe*",
    "cloudfront:Get*",
    "cloudfront:List*",
    "cloudfront-keyvaluestore:Describe*",
...
  "Sid": "cfReadOnly"
}
