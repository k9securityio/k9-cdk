import * as s3 from "@aws-cdk/aws-s3";
import {BucketPolicy} from "@aws-cdk/aws-s3";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";
import {AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";
import {getAllowedPrincipalArns} from "./aws-iam-utils";

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9DesiredAccess: Array<AccessSpec>
    readonly bucket: s3.Bucket
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadConfig,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);

export function makeBucketPolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): BucketPolicy {
    const policyFactory = new K9PolicyFactory();
    // If the bucket already has a policy, use it.  Maintaining the existing policy instance
    // is important because other CDK features like S3 autoDeleteObjects may have expressed dependencies
    // on that instance which must be maintained.
    const policy = props.bucket.policy ?
        props.bucket.policy :
        new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket});

    let resourceArns = [
        `${props.bucket.bucketArn}`,
        `${props.bucket.arnForObjects('*')}`
    ];

    const origAllowedAWSPrincipals = getAllowedPrincipalArns(policy.document);

    const allowStatements = policyFactory.makeAllowStatements("S3",
        SUPPORTED_CAPABILITIES,
        props.k9DesiredAccess,
        resourceArns);
    policy.document.addStatements(...allowStatements);


    const denyEveryoneElseTest = policyFactory.wasLikeUsed(props.k9DesiredAccess) ?
        'ArnNotLike' :
        'ArnNotEquals';
    const denyEveryoneElseStatement = new PolicyStatement({
                sid: 'DenyEveryoneElse',
                effect: Effect.DENY,
                principals: policyFactory.makeDenyEveryoneElsePrincipals(),
                actions: ['s3:*'],
                resources: resourceArns
            });
    const allAllowedPrincipalArns = policyFactory.getAllowedPrincipalArns(props.k9DesiredAccess);
    console.log(`origAllowedAWSPrincipals: ${origAllowedAWSPrincipals}`);
    for (let origAWSPrincipal of origAllowedAWSPrincipals){
        console.log(`adding origAWSPrincipal: ${origAWSPrincipal} to set of all Allowed Principal Arns`);
        allAllowedPrincipalArns.add(origAWSPrincipal);
    }
    console.log(`allAllowedPrincipalArns: ${[...allAllowedPrincipalArns]}`);
    denyEveryoneElseStatement.addCondition(denyEveryoneElseTest,
        {'aws:PrincipalArn': [...allAllowedPrincipalArns]});

    policy.document.addStatements(
        new PolicyStatement({
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
        denyEveryoneElseStatement,
    );

    policy.document.validateForResourcePolicy();

    return policy
}
