# Public S3 bucket exposure
Risk: a bucket with public read or write can leak sensitive data or be used to host malware.
Immediate actions: turn on S3 Block Public Access at account and bucket level, review the bucket policy and ACLs, check access logs for unexpected downloads.
Prevention: default encryption, least-privilege IAM, CloudTrail data events, AWS Config rule s3-bucket-public-read-prohibited, scan Terraform and CloudFormation with Checkov before deploy.
Triage: HIGH if the bucket holds sensitive data. MEDIUM for a public bucket with only static website content.
