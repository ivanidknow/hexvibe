# Vulnerable: IAM-AWS-AmazonNimbleStudio-LaunchProfileWorker
{
  "Action": [
    "ec2:DescribeNetworkInterfaces",
    "ec2:DescribeSecurityGroups",
    "fsx:DescribeFileSystems",
    "ds:DescribeDirectories"
  ],
  "Condition": {
...
  "Sid": "GetLaunchProfileInitializationDependencies"
}
