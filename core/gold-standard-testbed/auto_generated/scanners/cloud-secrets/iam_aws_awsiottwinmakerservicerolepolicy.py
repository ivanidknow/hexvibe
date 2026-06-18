# Vulnerable: IAM-AWS-AWSIoTTwinMakerServiceRolePolicy
{
  "Action": [
    "iotsitewise:ListAssets",
    "iotsitewise:ListAssetModels"
  ],
  "Effect": "Allow",
  "Resource": [
    "*"
...
  "Sid": "SiteWiseAssetModelAndAssetListAccess"
}
