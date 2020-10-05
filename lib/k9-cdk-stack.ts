import * as cdk from '@aws-cdk/core';
import * as s3 from '@aws-cdk/aws-s3'
import {BucketPolicy} from '@aws-cdk/aws-s3'
import {AnyPrincipal, Effect, PolicyStatement, PolicyStatementProps} from "@aws-cdk/aws-iam";

export type ArnEqualsTest = "ArnEquals"

export type ArnLikeTest = "ArnLike";

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;


/**
 * enum Direction {
   Up = "UP",
   Down = "DOWN",
   Left = "LEFT",
   Right = "RIGHT"
 }
 */
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
    // K9DesiredAccessSpecs may be able to replace K9AccessCapabilities in the near future
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
        "write-data",
        "delete-data"
    );

    getAccessSpec(accessCapability: AccessCapability, desiredCapabilities: K9AccessCapabilities): K9AccessSpec {
        switch (accessCapability) {
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
            case "delete-data":
                return {
                    accessCapability: "delete-data",
                    allowPrincipalArns: desiredCapabilities.allowDeleteDataArns ? desiredCapabilities.allowDeleteDataArns : new Set<string>(),
                    test: desiredCapabilities.allowDeleteDataTest ? desiredCapabilities.allowDeleteDataTest : "ArnEquals"
                };
            default:
                throw Error(`unsupported capability: ${accessCapability}`)
        }
    }


    makeBucketPolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): BucketPolicy {

        const policy = new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket});

        for (let accessCapability of this.SUPPORTED_CAPABILITIES) {
            let accessSpec = this.getAccessSpec(accessCapability, props.k9AccessCapabilities);
            let statement = makeAllowStatement(`Restricted-${accessCapability}`,
                this.getActions('S3', accessCapability),
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

    private getActions(service: string, accessCapabiilty: AccessCapability): Array<string> {
        switch (accessCapabiilty) {
            case "administer-resource":
                return ["s3:PutBucketPolicy",
                    "s3:PutBucketPublicAccessBlock"
                ];
            case "read-data":
                return ["s3:GetBucketPolicy"];
            case "write-data":
                return ["s3:PutObject"];
            case "delete-data":
                return ['s3:DeleteObject',
                    's3:DeleteObjectTagging',
                    's3:DeleteObjectVersion',
                    's3:DeleteObjectVersionTagging'
                ];
            default:
                throw Error(`unsupported capability: ${accessCapabiilty}`)
        }
    }
}

function makeAllowStatement(sid: string, actions: Array<string>, arns: Set<string>, test: ArnConditionTest) {
    let policyStatementProps:PolicyStatementProps = {
        sid: sid,
        effect: Effect.ALLOW
    };
    let statement = new PolicyStatement(policyStatementProps);
    statement.addActions(...actions);
    statement.addAnyPrincipal();
    statement.addAllResources();
    statement.addCondition(test, {'aws:PrincipalArn': new Array<string>(...arns)});
    return statement;
}

export class K9CdkStack extends cdk.Stack {
    // TODO - Remove stack definition.  We're not going to vend a stack.
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

    }
}