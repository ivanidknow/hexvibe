# Vulnerable: IAM-AWS-AmazonEventBridgeReadOnlyAccess
{
  "Action": [
    "events:DescribeRule",
    "events:DescribeEventBus",
    "events:DescribeEventSource",
    "events:ListEventBuses",
    "events:ListEventSources",
    "events:ListRuleNamesByTarget",
...
  "Resource": "*"
}
