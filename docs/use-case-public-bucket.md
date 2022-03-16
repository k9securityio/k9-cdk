# Least Privilege Access for a Public Bucket
You can use k9-cdk to make a bucket publicly readable with least privilege access
for named principals to administer, (full) read, write, and delete. The public will have the ability to 
call `S3:GetObject` on any object in the bucket.  See the [k9-cdk.ts](bin/k9-cdk.ts) for a full example. 

To make a bucket publicly readable, configure `K9BucketPolicyProps` properties:

* `publicReadAccess` to `true`
* `encryption` to `BucketEncryption.S3_MANAGED`

Configuring `encryption` to `BucketEncryption.S3_MANAGED` avoids needing to grant public read access to a KMS key. 

```typescript
const websiteK9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: websiteBucket,
    k9DesiredAccess: [/* normal k9 access capabilities */],
    publicReadAccess: true,
    encryption: BucketEncryption.S3_MANAGED,
};
```

When you configure `publicReadAccess` to `true`, the k9 policy generator will change its policy generation strategy in two ways.

First, an additional `AllowPublicReadAccess` statement allows all AWS principals (including anonymous) to use `S3:GetObject` (just like [AWS CDK Bucket#grantPublicAccess](https://github.com/aws/aws-cdk/blob/master/packages/%40aws-cdk/aws-s3/lib/bucket.ts#L807))
```json
{
    "Sid": "AllowPublicReadAccess",
    "Effect": "Allow",
    "Principal": {
        "AWS": "*"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::k9-cdk-public-website-test/*"
}
```

Second, the `DenyEveryoneElse` denies unwanted access to every action but `S3:GetObject`:
```json
{
    "Sid": "DenyEveryoneElse",
    "Effect": "Deny",
    "Principal": {
        "AWS": "*"
    },
    "NotAction": "s3:GetObject",
    "Resource": [
        "arn:aws:s3:::k9-cdk-public-website-test",
        "arn:aws:s3:::k9-cdk-public-website-test/*"
    ],
    "Condition": {
        "ArnNotEquals": {
            "aws:PrincipalArn": [
              "... snip your intended principals ..."
            ]
        }
    }
}
```

See the [k9-cdk.ts](bin/k9-cdk.ts) application for a full example.          



