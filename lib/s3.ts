import * as s3 from "@aws-cdk/aws-s3";
import {BucketEncryption} from "@aws-cdk/aws-s3";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";
import {AddToResourcePolicyResult, AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";
import * as aws_iam_utils from "./aws-iam-utils";

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9DesiredAccess: Array<AccessSpec>
    readonly bucket: s3.Bucket
    readonly encryption?: BucketEncryption
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadConfig,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);

export const SID_DENY_UNEXPECTED_ENCRYPTION_METHOD = 'DenyUnexpectedEncryptionMethod';

/**
 * Grants least-privilege access to a bucket by generating a BucketPolicy from the access capabilities
 * described by `props`; the policy will be set on the Bucket specified in `props`.
 * 
 * When a BucketPolicy already exists on the Bucket referenced in `props`:
 *   * the BucketPolicy's existing Statements will pass through unmodified
 *   * k9 will identify IAM principals there were allowed by the original policy and add those principals to
 *   the `DenyEveryoneElse` Statement's exclusion list so that, e.g. autoDeleteObjects works as expected
 *   * k9's Allow and Deny statements will be added to the policy
 *
 * @remarks
 *
 * k9 modifies the existing BucketPolicy in place instead of replacing or copying and modifying that
 * to preserve dependency references created by certain S3 CDK features such as `autoDeleteObjects`.
 *
 * @param scope The scope in which to define this construct.
 * @param id The scoped construct ID.
 * @param props describing the desired access capabilities for the bucket
 *
 * @return an array of AddToResourcePolicyResult
 */
export function grantAccessViaResourcePolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): AddToResourcePolicyResult[] {
    const policyFactory = new K9PolicyFactory();
    // If the bucket already has a policy, use it.  Maintaining the existing policy instance
    // is important because other CDK features like S3 autoDeleteObjects may have expressed dependencies
    // on that instance which must be maintained.
    if(!props.bucket.policy){
        props.bucket.policy = new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket})
    }
    const policy = props.bucket.policy;

    const addToResourcePolicyResults = new Array<AddToResourcePolicyResult>();
    let resourceArns = [
        `${props.bucket.bucketArn}`,
        `${props.bucket.arnForObjects('*')}`
    ];

    // Capture the principals that were allowed prior to modifying policy
    // One could argue this can be done at the end because we're going to
    // narrow the DenyEveryoneElse to the unique set of allowed principals.
    // Record here for now to preserve ability to generate fine-grained DenyEveryoneElse-$capability statements.
    const origAllowedAWSPrincipals = aws_iam_utils.getAllowedPrincipalArns(policy.document);

    // Make Allow Statements
    const k9Statements = policyFactory.makeAllowStatements("S3",
        SUPPORTED_CAPABILITIES,
        props.k9DesiredAccess,
        resourceArns);

    // Make Deny Statements
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
    for (let origAWSPrincipal of origAllowedAWSPrincipals){
        allAllowedPrincipalArns.add(origAWSPrincipal);
    }
    denyEveryoneElseStatement.addCondition(denyEveryoneElseTest,
        {'aws:PrincipalArn': [...allAllowedPrincipalArns]});

    // default encryption method to SSE-KMS,
    // allow override to SSE-S3 (AES256)
    let encryptionMethod = 'aws:kms'
    if(props.encryption){
        if(BucketEncryption.S3_MANAGED == props.encryption){
            encryptionMethod = 'AES256'
        }
    }
    k9Statements.push(
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
            sid: SID_DENY_UNEXPECTED_ENCRYPTION_METHOD,
            effect: Effect.DENY,
            principals: [new AnyPrincipal()],
            actions: ['s3:PutObject', 's3:ReplicateObject'],
            resources: resourceArns,
            conditions: {
                'StringNotEquals': {'s3:x-amz-server-side-encryption': encryptionMethod},
            },
        }),
        denyEveryoneElseStatement,
    );

    for(let statement of k9Statements){
        let addToResourcePolicyResult = props.bucket.addToResourcePolicy(statement);
        addToResourcePolicyResults.push(addToResourcePolicyResult);
    }

    policy.document.validateForResourcePolicy();

    return addToResourcePolicyResults;
}
