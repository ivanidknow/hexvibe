# Vulnerable: IAM-AWS-AWSChatbotServiceLinkedRolePolicy
{
  "Action": [
    "sns:ListSubscriptionsByTopic",
    "sns:ListTopics",
    "sns:Unsubscribe",
    "sns:Subscribe",
    "sns:ListSubscriptions"
  ],
...
  "Resource": "*"
}
