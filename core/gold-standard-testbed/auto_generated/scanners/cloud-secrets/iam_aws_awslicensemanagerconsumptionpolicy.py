# Vulnerable: IAM-AWS-AWSLicenseManagerConsumptionPolicy
{
  "Action": [
    "license-manager:CheckoutLicense",
    "license-manager:CheckInLicense",
    "license-manager:ExtendLicenseConsumption",
    "license-manager:GetLicense"
  ],
  "Effect": "Allow",
  "Resource": "*"
}
