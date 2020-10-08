import * as s3 from "@aws-cdk/aws-s3";
import {AccessCapability, K9AccessCapabilities, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";
import {BucketPolicy} from "@aws-cdk/aws-s3";
import {AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9AccessCapabilities: K9AccessCapabilities
    readonly bucket: s3.Bucket
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);

export function makeBucketPolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): BucketPolicy {
    const policyFactory = new K9PolicyFactory();
    const policy = new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket});

    let resourceArns = [
        `${props.bucket.bucketArn}`,
        `${props.bucket.bucketArn}/*`
    ];

    let allAllowedPrincipalArns = new Set<string>();
    for (let accessCapability of SUPPORTED_CAPABILITIES) {
        let accessSpec = policyFactory.getAccessSpec(accessCapability, props.k9AccessCapabilities);
        let statement = policyFactory.makeAllowStatement(`Restricted-${accessCapability}`,
            policyFactory.getActions('S3', accessCapability),
            accessSpec.allowPrincipalArns,
            accessSpec.test,
            resourceArns);
        policy.document.addStatements(statement);

        accessSpec.allowPrincipalArns.forEach(function (value) {
            allAllowedPrincipalArns.add(value);
        });
    }

    policy.document.addStatements(new PolicyStatement({
            sid: 'DenyInsecureCommunications',
            effect: Effect.DENY,
            principals: [new AnyPrincipal()],
            actions: ['s3:*'],
            resources: resourceArns,
            conditions: {
                Bool: {'aws:SecureTransport': false},
            },
        }),
        new PolicyStatement({
            sid: 'DenyUnencryptedStorage',
            effect: Effect.DENY,
            principals: [new AnyPrincipal()],
            actions: ['s3:PutObject', 's3:ReplicateObject'],
            resources: resourceArns,
            conditions: {
                Null: {'s3:x-amz-server-side-encryption': true},
            },
        }),
        new PolicyStatement({
            sid: 'DenyStorageWithoutKMSEncryption',
            effect: Effect.DENY,
            principals: [new AnyPrincipal()],
            actions: ['s3:PutObject', 's3:ReplicateObject'],
            resources: resourceArns,
            conditions: {
                'StringNotEquals': {'s3:x-amz-server-side-encryption': 'aws:kms'},
            },
        }),
        new PolicyStatement({
            sid: 'DenyEveryoneElse',
            effect: Effect.DENY,
            principals: [new AnyPrincipal()],
            actions: ['s3:*'],
            resources: resourceArns,
            conditions: {
                ArnNotEquals: {'aws:PrincipalArn': [...allAllowedPrincipalArns]},
            },
        })
    );

    policy.document.validateForResourcePolicy();

    return policy
}
