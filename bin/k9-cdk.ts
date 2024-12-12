#!/usr/bin/env node

import * as cdk from "aws-cdk-lib";
import {RemovalPolicy, Tags} from "aws-cdk-lib";
// import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
// import * as cforigins from "aws-cdk-lib/aws-cloudfront-origins";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import {BlockPublicAccess, BucketEncryption} from "aws-cdk-lib/aws-s3";

import * as k9 from "../lib";

const administerResourceArns = [
    // for development
    "arn:aws:iam::139710491120:user/ci",
    "arn:aws:iam::139710491120:user/skuenzli",
    "arn:aws:iam::139710491120:role/k9-dev-appeng",
    "arn:aws:iam::139710491120:role/cdk-hnb659fds-cfn-exec-role-139710491120-us-east-1"
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
    "arn:aws:sts::139710491120:assumed-role/k9-dev-appeng/console"
];

const readDataArns = [
    "arn:aws:iam::123456789012:role/customer-service"
];

const app = new cdk.App(
    // Can configure features with an AppProps:
    // https://docs.aws.amazon.com/cdk/api/latest/docs/@aws-cdk_core.AppProps.html
);

const stack = new cdk.Stack(app, 'K9PolicyLibV2IntegrationTest');
const bucket = new s3.Bucket(stack, 'TestBucket', {
    bucketName: 'k9-cdk-v2-internal-bucket-test',
    removalPolicy: RemovalPolicy.DESTROY,
});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_CONFIG,
            allowPrincipalArns: readConfigArns,
        },
        {
            accessCapabilities: [
                k9.k9policy.AccessCapability.READ_DATA,
                k9.k9policy.AccessCapability.WRITE_DATA
                ],
            allowPrincipalArns: readWriteDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_DATA,
            allowPrincipalArns: readDataArns,
        }
        // omit access spec for delete-data because it is unneeded
    )
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);

const websiteBucket = new s3.Bucket(stack, 'WebsiteBucket', {
    bucketName: 'k9-cdk-v2-public-website-test',
    removalPolicy: RemovalPolicy.DESTROY,
    encryption: BucketEncryption.S3_MANAGED,
    blockPublicAccess: new BlockPublicAccess({
        blockPublicPolicy: false
    })
});

const websiteK9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: websiteBucket,
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess.concat([]),
    publicReadAccess: true,
    encryption: BucketEncryption.S3_MANAGED,
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3PublicWebsite", websiteK9BucketPolicyProps);

const autoDeleteBucket = new s3.Bucket(stack, 'AutoDeleteBucket', {
    bucketName: 'k9-cdk-v2-auto-delete-test',
    removalPolicy: RemovalPolicy.DESTROY,
    autoDeleteObjects: true,
});

console.log(`original autoDeleteBucket.policy: ${autoDeleteBucket.policy}`);
const k9AutoDeleteBucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: autoDeleteBucket,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_CONFIG,
            allowPrincipalArns: readConfigArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
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
    alias: 'k9-cdk-v2-integration-test',
    policy: keyPolicy,
});

// Created test distribution manually because I haven't fully sorted through
// https://github.com/aws/aws-cdk/issues/21771
//
// let cloudfrontDistribution = new cloudfront.Distribution(stack, 'oac-bucket-dist', {
//     comment: 'k9-cdk integration test distribution for CloudFront OAC',
//     defaultBehavior: {
//         origin: new cforigins.S3Origin(cloudfrontOACBucket, {
//
//         }),
//     },
// });
let cloudfrontDistributionId = 'E1OHGXOERP1X0D'
let cloudfrontDistributionArn = `arn:aws:cloudfront::${stack.account}:distribution/${cloudfrontDistributionId}`
// let cloudfrontDistributionArn = `arn:aws:cloudfront::${stack.account}:distribution/${cloudfrontDistribution.distributionId}`

const cloudfrontOACk9KeyPolicyProps: k9.kms.K9KeyPolicyProps = {
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess,
    trustAccountIdentities: false,
    awsServiceAccessGenerators: new Array<k9.k9policy.IAWSServiceAccessGenerator>(
        new k9.kms.CloudFrontOACReadAccessGenerator(cloudfrontDistributionArn),
    )
};
const cloudfrontOACKeyPolicy = k9.kms.makeKeyPolicy(cloudfrontOACk9KeyPolicyProps);

const cloudfrontOACKey = new kms.Key(stack, 'CloudFrontOACKMSKey', {
    alias: 'k9-cdk-v2-cloudfront-oac-test',
    policy: cloudfrontOACKeyPolicy,
});

const cloudfrontOACBucket = new s3.Bucket(stack, 'CloudFrontOACBucket', {
    bucketName: 'k9-cdk-v2-cloudfront-oac-test',
    removalPolicy: RemovalPolicy.DESTROY,
    encryption: BucketEncryption.KMS,
    encryptionKey: cloudfrontOACKey
});

const cloudfrontOACBucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: cloudfrontOACBucket,
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess.concat([]),
    encryption: BucketEncryption.KMS_MANAGED,
    awsServiceAccessGenerators: new Array<k9.k9policy.IAWSServiceAccessGenerator>(
      new k9.s3.CloudFrontOACReadAccessGenerator(cloudfrontOACBucket, cloudfrontDistributionArn),
    )
};

k9.s3.grantAccessViaResourcePolicy(stack, "CloudFrontOACBucket", cloudfrontOACBucketPolicyProps);

// Demonstrate generating and applying a DynamoDB resource policy
const ddbResourcePolicyProps: k9.dynamodb.K9DynamoDBResourcePolicyProps = {
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_CONFIG,
            allowPrincipalArns: readConfigArns.concat([
                "arn:aws:iam::139710491120:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer"
            ]),
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_DATA,
            allowPrincipalArns: readWriteDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
            allowPrincipalArns: readWriteDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.DELETE_DATA,
            allowPrincipalArns: readWriteDataArns,
        },
    )
};


const ddbResourcePolicy = k9.dynamodb.makeResourcePolicy(ddbResourcePolicyProps);

const table = new dynamodb.TableV2(stack, 'k9-cdk-v2-int-test', {
  partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
  removalPolicy: cdk.RemovalPolicy.DESTROY,
  resourcePolicy: ddbResourcePolicy
});


for (let construct of [bucket,
    websiteBucket,
    autoDeleteBucket,
    key,
    // cloudfrontDistribution,
    cloudfrontOACBucket,
    cloudfrontOACKey,
    table,
]) {
    Tags.of(construct).add('k9security:analysis', 'include');
}
