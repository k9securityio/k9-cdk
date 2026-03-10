# k9 AWS CDK policy library #

k9 Security's `k9-cdk` for CDKv2 ([CDKv1](https://github.com/k9securityio/k9-cdk/tree/main)) makes strong security usable and helps you provision best practice AWS security policies 
defined using the simplified [k9 access capability model](https://k9security.io/docs/k9-access-capability-model/) and
safe defaults.  In CDK terms, this library provides [Curated (L2) constructs](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html) that wrap core CloudFormation resources (L1) to simplify security.

Supported services:

* S3
* KMS
* DynamoDB
* SQS
* EventBridge

This library [simplifies IAM as described in Effective IAM for AWS](https://www.effectiveiam.com/simplify-aws-iam) and is fully-supported by k9 Security. We're happy to answer questions or help you integrate it via a [GitHub issue](https://github.com/k9securityio/k9-cdk/issues) or email to [support@k9security.io](mailto:support@k9security.io?subject=k9-cdk). 

## Usage
Use the k9 CDK to generate a policy and use it in your existing code base.

For example, the following code will:

1. provision an S3 Bucket
2. allow the `ci` and `person1` users to administer the bucket
3. allow administrators and `k9-auditor` to read bucket configuration
4. allow the `app-backend` role to write data into the bucket
5. allow the `app-backend` and `customer-service` role to read data in the bucket

```typescript
import * as cdk from "aws-cdk-lib";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as k9 from "@k9securityio/k9-cdk";

// Define which principals may access the bucket and what capabilities they should have
const administerResourceArns = [
    "arn:aws:iam::123456789012:user/ci", 
    "arn:aws:iam::123456789012:user/person1"
];

const readConfigArns = administerResourceArns.concat([
    "arn:aws:iam::123456789012:role/k9-auditor",
    "arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer"
]);

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9Example');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
         {   // declare access capabilities individually
             accessCapability: k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
             allowPrincipalArns: administerResourceArns,
         },
         {
             accessCapability: k9.k9policy.AccessCapability.READ_CONFIG,
             allowPrincipalArns: readConfigArns,
         },
        {  // or declare multiple access capabilities at once
            accessCapabilities: [
                k9.k9policy.AccessCapability.READ_DATA,
                k9.k9policy.AccessCapability.WRITE_DATA
                ],
            allowPrincipalArns: [
                "arn:aws:iam::123456789012:role/app-backend",
            ],
        },
         {
             accessCapability: k9.k9policy.AccessCapability.READ_DATA,
             allowPrincipalArns: [
                 "arn:aws:iam::123456789012:role/customer-service"
             ],
         }
         // omit access spec for delete-data because it is unneeded
     )
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);
```

Granting access to an SQS queue works the same way, using the `k9.sqs.grantAccessViaResourcePolicy` function:
```typescript
import * as sqs from 'aws-cdk-lib/aws-sqs';
const queue = new sqs.Queue(stack, 'Queue', {
        queueName: 'app-queue-with-k9-policy',
});

const k9SQSResourcePolicyProps: K9SQSResourcePolicyProps = {
    queue: queue,
    // reuse bucket's desired access for brevity; configure k9DesiredAccess however you need
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess,
};

k9.sqs.grantAccessViaResourcePolicy(k9SQSResourcePolicyProps);
```

Granting access to a KMS key is similar, but the custom resource policy is created first 
so it can be set via `props` per CDK convention:
 
```typescript
import * as kms from "aws-cdk-lib/aws-kms"; 
import {PolicyDocument} from "aws-cdk-lib/aws-iam";

const k9KeyPolicyProps: k9.kms.K9KeyPolicyProps = {
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess
};
const keyPolicy: PolicyDocument = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

new kms.Key(stack, 'KMSKey', {
    alias: 'app-key-with-k9-policy',
    policy: keyPolicy
}); 
```

Protecting a DynamoDB table follows the same path as KMS, generating a policy then providing it to the DynamoDB table construct via props:

```typescript
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";

const ddbResourcePolicyProps: k9.dynamodb.K9DynamoDBResourcePolicyProps = {
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess
};


const ddbResourcePolicy = k9.dynamodb.makeResourcePolicy(ddbResourcePolicyProps);

const table = new dynamodb.TableV2(stack, 'app-table-with-k9-policy', {
  partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
  resourcePolicy: ddbResourcePolicy,
});
```

Granting access to an EventBridge event bus works like SQS, using the `k9.events.grantAccessViaResourcePolicy` function.
EventBridge supports the `administer-resource`, `read-config`, and `write-data` capabilities:

```typescript
import * as events from "aws-cdk-lib/aws-events";

const bus = new events.EventBus(stack, 'AppEventBus', {
    eventBusName: 'app-bus-with-k9-policy',
});

const k9EventBusProps: k9.events.K9EventBusResourcePolicyProps = {
    bus: bus,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: [
                k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
                k9.k9policy.AccessCapability.READ_CONFIG,
            ],
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
            allowPrincipalArns: [
                "arn:aws:iam::123456789012:role/app-backend",
            ],
        },
    ),
};

k9.events.grantAccessViaResourcePolicy(k9EventBusProps);
```

## Example stack

The example stack demonstrates full use of the k9 S3, KMS, DynamoDB, SQS, and EventBridge policy generators.  Generated policies:

S3 Bucket Policy:

* [Templatized Bucket Policy](examples/generated.bucket-policy.json)
* [BucketPolicy resource in CFn template](examples/K9Example.template.json)

SQS Queue Policy:

* [Templatized Queue Policy](examples/generated.queue-policy.json)
* [TestQueuePolicy resource in CFn template](examples/K9Example.template.json)

KMS Key Policy:

* [Templatized Key Policy](examples/generated.key-policy.json)
* [KeyPolicy attribute of Key resource in CFn template](examples/K9Example.template.json)

DynamoDB Resource Policy:

* [Templatized DynamoDB Resource Policy](examples/generated.dynamodb-policy.json)
* [ResourcePolicy attribute of GlobalTable resource in CFn template](examples/K9Example.template.json)


## Restricting Access to Specific Organizations

You can restrict access capabilities to principals within specific AWS Organizations by setting `restrictToPrincipalOrgIDs` on an `IAccessSpec`. When set, k9-cdk will:

1. Add a `StringEquals` condition on `aws:PrincipalOrgID` to the Allow statements for those capabilities
2. Generate a `DenyUntrustedOrgs` statement that explicitly denies the org-restricted actions for principals outside the specified organizations

This provides defense-in-depth: even if another Allow statement is added to the policy without an org constraint, the explicit Deny prevents principals from untrusted organizations from gaining access _for those permissions_.

`restrictToPrincipalOrgIDs` can be combined with specific principal ARNs (both conditions must be satisfied) or with a wildcard `*` principal to allow any principal within the organization:

```typescript
const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: [
                k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
                k9.k9policy.AccessCapability.READ_CONFIG,
            ],
            allowPrincipalArns: administerResourceArns,
        },
        {   // restrict write-data to specific principals within the org
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
            allowPrincipalArns: [
                "arn:aws:iam::123456789012:role/app-backend",
            ],
            restrictToPrincipalOrgIDs: ["o-abc123"],
        },
        {   // allow any principal in the org to read data
            accessCapabilities: k9.k9policy.AccessCapability.READ_DATA,
            allowPrincipalArns: ["*"],
            restrictToPrincipalOrgIDs: ["o-abc123"],
        },
    ),
};
```

In this example, the `write-data` Allow statement requires the caller to match both the specific principal ARN and the org ID. The `read-data` Allow statement allows any principal from `o-abc123`. Both capabilities are covered by the `DenyUntrustedOrgs` statement, which denies the corresponding actions for principals outside `o-abc123`.

**Caveat:** When you use a wildcard `*` principal with `restrictToPrincipalOrgIDs`, k9-cdk will _not_ generate a `DenyEveryoneElse` statement. The `DenyEveryoneElse` statement works by excepting specific principal ARNs from the deny, but a `*` wildcard principal cannot be meaningfully excepted because exempting `*` would exempt everyone and render the deny ineffective. In this case, access is constrained by the `aws:PrincipalOrgID` condition on the Allow statements and the `DenyUntrustedOrgs` deny statement rather than `DenyEveryoneElse`. As an alternative, you can specify principal ARNs with wildcards and test with `ArnLike`:

```typescript
{   // restrict write-data to all 'publisher' principals within the org
    accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
    allowPrincipalArns: [
        "arn:aws:iam::*:role/*publisher*",
    ],
    restrictToPrincipalOrgIDs: ["o-abc123"],
}
```

That's not every principal in the org, but it may be closer to what you want in practice.

## Specialized Use Cases

k9-cdk can be configured to support specialized use cases, including:
* [Public Bucket](docs/use-case-public-bucket.md) - Publicly readable objects, least privilege for all other actions 

## Local Development and Testing

The high level build commands for this project are driven by `make`:

* `make all` - build library, run tests, and deploy 
* `make build` - build the library 
* `make converge` - deploy the integration test resources
* `make destroy` - destroy the integration test resources

The low level build commands for this project are:

* `npx projen build`   compile typescript to js, lint, transpile with JSII, execute tests
* `cdk synth`       emits the synthesized CloudFormation template
* `cdk deploy`      deploy this stack to your default AWS account/region
* `cdk diff`        compare deployed stack with current state
