# k9 AWS CDK policy library #

k9 Security's `k9-cdk` makes strong security usable and helps you provision best practice AWS security policies 
defined using the simplified [k9 access capability model](https://k9security.io/docs/k9-access-capability-model/) and
safe defaults.  In CDK terms, this library provides [Curated (L2) constructs](https://docs.aws.amazon.com/cdk/latest/guide/getting_started.html) that wrap core CloudFormation resources (L1) to simplify security.

Supported services:

* S3
* KMS

## Usage
Use the k9 CDK to generate a policy and use it in your existing code base.

For example, the following code will:

1. provision an S3 Bucket
2. allow the `ci` and `person1` users to administer the bucket
3. allow administrators and `k9-auditor` to read bucket configuration
4. allow the `app-backend` role to write data into the bucket
5. allow the `app-backend` and `customer-service` role to read data in the bucket

```typescript
import * as cdk from "@aws-cdk/core";
import * as s3 from "@aws-cdk/aws-s3";
import * as k9 from "@k9securityio/k9-cdk";

// Define which principals may access the bucket and what capabilities they should have
const administerResourceArns = new Set<string>([
        "arn:aws:iam::12345678910:user/ci", 
        "arn:aws:iam::12345678910:user/person1"
    ]
);

const readConfigArns = new Set<string>(administerResourceArns)
    .add("arn:aws:iam::12345678910:role/k9-auditor");

const writeDataArns = new Set<string>([
        "arn:aws:iam::12345678910:role/app-backend",
    ]
);
const readDataArns = new Set<string>(writeDataArns)
    .add("arn:aws:iam::12345678910:role/customer-service");

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9Example');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.AccessSpec>(
         {
             accessCapability: k9.k9policy.AccessCapability.AdministerResource,
             allowPrincipalArns: administerResourceArns,
         },
         {
             accessCapability: k9.k9policy.AccessCapability.ReadConfig,
             allowPrincipalArns: readConfigArns,
         },
         {
             accessCapability: k9.k9policy.AccessCapability.WriteData,
             allowPrincipalArns: writeDataArns,
         },
         {
             accessCapability: k9.k9policy.AccessCapability.ReadData,
             allowPrincipalArns: readDataArns,
         }
         // omit access spec for delete-data because it is unneeded
     )
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);
```

Granting access to a KMS key is similar, but the custom resource policy is created first 
so it can be set via `props` per CDK convention:
 
```typescript
import * as kms from "@aws-cdk/aws-kms"; 
import {PolicyDocument} from "@aws-cdk/aws-iam";

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

## Local Development and Testing

The high level build commands for this project are driven by `make`:

* `make all` - build library, run tests, and deploy 
* `make build` - build the library 
* `make unit-test` - run unit tests for the library
* `make converge` - deploy the integration test resources
* `make destroy` - destroy the integration test resources
* `make publish` - publish the package to npmjs

The low level build commands for this project are:

 * `npm run build`   compile typescript to js
 * `npm run watch`   watch for changes and compile
 * `npm run test`    perform the jest unit tests
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk synth`       emits the synthesized CloudFormation template
