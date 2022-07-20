# k9 AWS CDK policy library #

k9 Security's `k9-cdk` for CDKv2 makes strong security usable and helps you provision best practice AWS security policies 
defined using the simplified [k9 access capability model](https://k9security.io/docs/k9-access-capability-model/) and
safe defaults.  In CDK terms, this library provides [Curated (L2) constructs](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html) that wrap core CloudFormation resources (L1) to simplify security.

Supported services:

* S3
* KMS

This library [simplifies IAM as described in Effective IAM for AWS](https://www.effectiveiam.com/simplify-aws-iam) and is fully-supported by k9 Security. We're happy to answer questions or help you integrate it via a [GitHub issue](https://github.com/k9securityio/k9-cdk/issues) or email to [support@k9security.io](mailto:support@k9security.io?subject="k9-cdk"). 

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
    "arn:aws:iam::123456789012:role/k9-auditor"
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

The example stack demonstrates full use of the k9 S3 and KMS policy generators.  Generated policies:

S3 Bucket Policy:
* [Templatized Bucket Policy](examples/generated.bucket-policy.json)
* [BucketPolicy resource in CFn template](examples/K9Example.template.json)

KMS Key Policy:
* [Templatized Key Policy](examples/generated.key-policy.json)
* [KeyPolicy attribute of Key resource in CFn template](examples/K9Example.template.json)

## Specialized Use Cases

k9-cdk can be configured to support specialized use cases, including:
* [Public Bucket](docs/use-case-public-bucket.md) - Publicaly readable objects, least privilege for all other actions 

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
