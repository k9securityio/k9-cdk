import * as s3 from "@aws-cdk/aws-s3";
import {BucketPolicy} from "@aws-cdk/aws-s3";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";
import {AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9DesiredAccess: Array<AccessSpec>
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

    let accessSpecsByCapability: Map<AccessCapability, AccessSpec> = new Map<AccessCapability, AccessSpec>();

    props.k9DesiredAccess.forEach(accessSpec => accessSpecsByCapability.set(accessSpec.accessCapability, accessSpec));

    for (let supportedCapability of SUPPORTED_CAPABILITIES) {
        let accessSpec: AccessSpec = accessSpecsByCapability.get(supportedCapability) ||
            { //generate a default access spec if none was provided
                accessCapability: supportedCapability,
                allowPrincipalArns: new Set<string>(),
                test: "ArnEquals"
            }
        ;
        let arnConditionTest = accessSpec.test || "ArnEquals";
        let statement = policyFactory.makeAllowStatement(`Restricted-${supportedCapability}`,
            policyFactory.getActions('S3', supportedCapability),
            accessSpec.allowPrincipalArns,
            arnConditionTest,
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
