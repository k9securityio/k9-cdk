# aws:PrincipalOrgID Condition Key Support

Research conducted for CLOUD-3520 to verify that all AWS services supported by k9-cdk can use the `aws:PrincipalOrgID` global condition key in resource policies.

## Summary

`aws:PrincipalOrgID` is an [AWS global condition context key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) available across all AWS services. It is included in the request context whenever the calling principal is a member of an AWS Organization. All five services supported by k9-cdk support this key in their resource policies.

| Service | `aws:PrincipalOrgID` Supported | `aws:PrincipalOrgPaths` Supported | Key Caveat |
|---|---|---|---|
| S3 (bucket policies) | Yes | Yes | Blocks AWS service principals |
| KMS (key policies) | Yes | Yes | Blocks AWS service principals |
| DynamoDB (resource policies) | Yes | Yes | Standard global key behavior |
| SQS (queue policies) | Yes | **No** | `aws:PrincipalOrgPaths` not supported |
| EventBridge (event bus policies) | Yes | Not via simplified API | Only condition key in PutPermission simplified API |

## Per-Service Details

### S3 (Bucket Policies)

S3 bucket policies fully support `aws:PrincipalOrgID`. AWS provides [official examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html) showing its use.

**Caveat**: This condition blocks AWS service principals (e.g., CloudTrail writing logs), since they are not members of your organization. Combine with `aws:PrincipalIsAWSService` to handle service principals.

### KMS (Key Policies)

KMS supports all AWS global condition keys including `aws:PrincipalOrgID`. The [KMS documentation](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-aws.html) states: "AWS KMS supports all global condition keys."

**Caveat**: AWS services calling KMS on behalf of users (e.g., for encryption/decryption) do so from internal AWS accounts outside your org. If your key policy uses a Deny with `aws:PrincipalOrgID` as the only condition, it can block AWS services from using the key.

### DynamoDB (Resource Policies)

DynamoDB resource-based policies support `aws:PrincipalOrgID`. The [DynamoDB IAM documentation](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/security_iam_service-with-iam.html) confirms support for AWS-wide condition keys and explicitly mentions `aws:PrincipalOrgID`.

### SQS (Queue Policies)

SQS queue policies support `aws:PrincipalOrgID`. The [SQS least-privilege policy documentation](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-least-privilege-policy.html) references it.

**Notable limitation**: SQS does **not** support `aws:PrincipalOrgPaths`. If OU-level granularity is needed with SQS, use a different approach (e.g., listing account IDs or `aws:PrincipalArn` patterns). See [k9 Security guide for SQS in same OU](https://www.k9security.io/docs/send-message-to-encrypted-sqs-queue-in-same-ou/).

### EventBridge (Event Bus Policies)

EventBridge event bus policies support `aws:PrincipalOrgID`. When using the [PutPermission API](https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutPermission.html) simplified form, `aws:PrincipalOrgID` is the **only** supported condition key with `StringEquals` as the only supported operator. Full resource-based policies (via the `Policy` parameter) support additional condition keys.

## Cross-Cutting Considerations

### AWS Service Principals

AWS service principals (e.g., `cloudtrail.amazonaws.com`, `delivery.logs.amazonaws.com`) are **not** members of your organization. `aws:PrincipalOrgID` conditions will not match them.

**k9-cdk mitigation**: DenyEveryoneElse statements include `aws:PrincipalIsAWSService: false`, so service principals are not blocked by Deny statements. For wildcard+org patterns, DenyEveryoneElse is skipped entirely.

### Anonymous/Unauthenticated Requests

The key is **not** present in the request context for anonymous requests, so conditions using this key will not match anonymous callers.

### Management Account

The management account of an organization **is** matched by `aws:PrincipalOrgID`.

### Sensitive Condition Key

AWS classifies `aws:PrincipalOrgID` as a "sensitive" condition key. Always use `StringEquals` with exact organization IDs -- wildcards in the value have no valid use case.

## References

- [AWS global condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- [AWS global condition keys - KMS Developer Guide](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-aws.html)
- [Amazon S3 bucket policy examples](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [DynamoDB IAM integration](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/security_iam_service-with-iam.html)
- [SQS least-privilege access policies](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-least-privilege-policy.html)
- [EventBridge event bus permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-permissions-manage.html)
- [Control access using aws:PrincipalOrgID - AWS Security Blog](https://aws.amazon.com/blogs/security/control-access-to-aws-resources-by-using-the-aws-organization-of-iam-principals/)
- [Send message to encrypted SQS queue in same OU - k9 Security](https://www.k9security.io/docs/send-message-to-encrypted-sqs-queue-in-same-ou/)
