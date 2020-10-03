import * as cdk from '@aws-cdk/core';
import * as s3 from '@aws-cdk/aws-s3'
import {BucketPolicy} from '@aws-cdk/aws-s3'
import {AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";

export type ArnEqualsTest = "ArnEquals"

export type ArnLikeTest = "ArnLike";

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;


export type AccessCapabilityAdministerResource = "administer-resource"
export type AccessCapabilityReadData = "read-data"
export type AccessCapabilityWriteData = "write-data"
export type AccessCapabilityDeleteData = "delete-data"

export type AccessCapability =
    | AccessCapabilityAdministerResource
    | AccessCapabilityReadData
    | AccessCapabilityWriteData
    | AccessCapabilityDeleteData

export interface K9AccessSpec {
    accessCapability: AccessCapability
    allowPrincipalArns: Set<string>
    test: ArnConditionTest
}

export interface K9DesiredAccessSpecs {
    [accessCapability: string]: K9AccessSpec;
}

export class K9AccessCapabilities {

    constructor(
        readonly allowAdministerResourceArns?: Set<string>,
        readonly allowAdministerResourceTest?: ArnConditionTest,
        readonly allowReadDataArns?: Set<string>,
        readonly allowReadDataTest?: ArnConditionTest,
        readonly allowWriteDataArns?: Set<string>,
        readonly allowWriteDataTest?: ArnConditionTest,
        readonly allowDeleteDataArns?: Set<string>,
        readonly allowDeleteDataTest?: ArnConditionTest,
    ) {

    }

    // ??? Add support for custom actions
    // will probably encourage users to create custom statements directly using the policy instead of trying to model
}

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9AccessCapabilities: K9AccessCapabilities
    readonly bucket: s3.Bucket
}

export class K9PolicyFactory {

    SUPPORTED_CAPABILITIES = Array<AccessCapability>(
        "administer-resource",
        "read-data",
        "write-data"
    );

    getAccessSpec(k9_capability: string, desiredCapabilities: K9AccessCapabilities): K9AccessSpec {
        switch (k9_capability) {
            case "administer-resource":
                return {
                    accessCapability: "administer-resource",
                    allowPrincipalArns: desiredCapabilities.allowAdministerResourceArns ? desiredCapabilities.allowAdministerResourceArns : new Set<string>(),
                    test: desiredCapabilities.allowAdministerResourceTest ? desiredCapabilities.allowAdministerResourceTest : "ArnEquals"
                };
            case "read-data":
                return {
                    accessCapability: "read-data",
                    allowPrincipalArns: desiredCapabilities.allowReadDataArns ? desiredCapabilities.allowReadDataArns : new Set<string>(),
                    test: desiredCapabilities.allowReadDataTest ? desiredCapabilities.allowReadDataTest : "ArnEquals"
                };
            case "write-data":
                return {
                    accessCapability: "write-data",
                    allowPrincipalArns: desiredCapabilities.allowWriteDataArns ? desiredCapabilities.allowWriteDataArns : new Set<string>(),
                    test: desiredCapabilities.allowWriteDataTest ? desiredCapabilities.allowWriteDataTest : "ArnEquals"
                };
            default:
                throw Error(`unsupported capability: ${k9_capability}`)
        }
    }


    makeBucketPolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): BucketPolicy {

        const policy = new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket});

        for (let access_capability of this.SUPPORTED_CAPABILITIES) {
            let accessSpec = this.getAccessSpec(access_capability, props.k9AccessCapabilities);
            let statement = makeAllowStatement(`Restricted-${access_capability}`,
                ["s3:GetBucketPolicy"],
                accessSpec.allowPrincipalArns,
                accessSpec.test);
            policy.document.addStatements(statement)

        }

        policy.document.addStatements(new PolicyStatement({
                effect: Effect.DENY,
                principals: [new AnyPrincipal()],
                actions: ['*'],
                resources: [`${props.bucket.bucketArn}/*`],
                conditions: {
                    Bool: {'aws:SecureTransport': false},
                },
            })
        );

        policy.document.validateForResourcePolicy();
        console.log("validated resource policy");

        return policy
    }
}

function makeAllowStatement(sid: string, actions: Array<string>, arns: Set<string>, test: ArnConditionTest) {
    let statement = new PolicyStatement();
    statement.sid = sid;
    statement.addActions(...actions);
    statement.effect = Effect.ALLOW;
    statement.addAnyPrincipal();
    statement.addAllResources();
    for (let arn of arns) {
        console.log(arn);
        statement.addCondition(test, {'aws:PrincipalArn': arn})
    }
    return statement;
}

export class K9CdkStack extends cdk.Stack {
    // TODO - Remove stack definition.  We're not going to vend a stack.
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

    }
}