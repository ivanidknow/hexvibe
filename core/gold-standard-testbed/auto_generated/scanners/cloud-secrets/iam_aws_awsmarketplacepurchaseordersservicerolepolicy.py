# Vulnerable: IAM-AWS-AWSMarketplacePurchaseOrdersServiceRolePolicy
{
  "Action": [
    "purchase-orders:ViewPurchaseOrders",
    "purchase-orders:ModifyPurchaseOrders"
  ],
  "Effect": "Allow",
  "Resource": [
    "*"
...
  "Sid": "AllowPurchaseOrderActions"
}
