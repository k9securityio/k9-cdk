#!/usr/bin/env node

import * as cdk from "@aws-cdk/core";
import {RemovalPolicy, Tags} from "@aws-cdk/core";
import * as kms from "@aws-cdk/aws-kms";
import * as s3 from "@aws-cdk/aws-s3";
import {BucketEncryption} from "@aws-cdk/aws-s3";

import * as k9 from "../lib";

const administerResourceArns = [
    // for development
    "arn:aws:iam::139710491120:user/ci",
    "arn:aws:iam::139710491120:user/skuenzli",
    "arn:aws:sts::139710491120:federated-user/skuenzli",
    "arn:aws:iam::139710491120:role/k9-dev-appeng",
    "arn:aws:sts::139710491120:assumed-role/k9-dev-appeng/console"
];

const readConfigArns = administerResourceArns.concat(
    [
        "arn:aws:iam::139710491120:role/k9-auditor",     // for audit
        "arn:aws:iam::139710491120:role/k9-backend-dev"  // for integration tests
    ]
);

const readWriteDataArns = [
    "arn:aws:iam::123456789012:role/app-backend",
    "arn:aws:iam::139710491120:role/k9-dev-appeng",
    "arn:aws:sts::139710491120:assumed-role/k9-dev-appeng/console",
];

const readDataArns = [
    "arn:aws:iam::123456789012:role/customer-service"
];

const app = new cdk.App(
    // Can configure features with an AppProps:
    // https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_core.AppProps.html
);

const stack = new cdk.Stack(app, 'K9PolicyLibV1IntegrationTest');
const bucket = new s3.Bucket(stack, 'TestBucket', {
    bucketName: 'k9-cdk-v1-internal-bucket-test',
    removalPolicy: RemovalPolicy.DESTROY,
});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.AccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.ReadConfig,
            allowPrincipalArns: readConfigArns,
        },
        {
            accessCapabilities: [
                k9.k9policy.AccessCapability.ReadData,
                k9.k9policy.AccessCapability.WriteData
                ],
            allowPrincipalArns: readWriteDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.ReadData,
            allowPrincipalArns: readDataArns,
        }
        // omit access spec for delete-data because it is unneeded
    )
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);

const websiteBucket = new s3.Bucket(stack, 'WebsiteBucket', {
    bucketName: 'k9-cdk-v1-public-website-test',
    removalPolicy: RemovalPolicy.DESTROY,
    encryption: BucketEncryption.S3_MANAGED,
});

const websiteK9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: websiteBucket,
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess.concat([]),
    publicReadAccess: true,
    encryption: BucketEncryption.S3_MANAGED,
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3PublicWebsite", websiteK9BucketPolicyProps);

const autoDeleteBucket = new s3.Bucket(stack, 'AutoDeleteBucket', {
    bucketName: 'k9-cdk-v1-auto-delete-test',
    removalPolicy: RemovalPolicy.DESTROY,
    autoDeleteObjects: true,
});

console.log(`original autoDeleteBucket.policy: ${autoDeleteBucket.policy}`);
const k9AutoDeleteBucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: autoDeleteBucket,
    k9DesiredAccess: new Array<k9.k9policy.AccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.ReadConfig,
            allowPrincipalArns: readConfigArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WriteData,
            allowPrincipalArns: readWriteDataArns,
        }
    )
};

k9.s3.grantAccessViaResourcePolicy(stack, 'AutoDeleteBucket', k9AutoDeleteBucketPolicyProps);

console.log(`k9 autoDeleteBucket.policy: ${autoDeleteBucket.policy}`);

// Now create a Key policy that grants access the same access
const k9KeyPolicyProps: k9.kms.K9KeyPolicyProps = {
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess,
    //trustAccountIdentities: true  // the effective default
    trustAccountIdentities: false
};
const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

// Set CDK preference @aws-cdk/aws-kms:defaultKeyPolicies to true in cdk.json
const key = new kms.Key(stack, 'KMSKey', {
    alias: 'k9-cdk-v1-integration-test',
    policy: keyPolicy,
});

for(let construct of [bucket, websiteBucket, autoDeleteBucket, key]){
    Tags.of(construct).add('k9security:analysis', 'include');
}
