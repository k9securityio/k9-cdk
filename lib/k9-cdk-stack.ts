import * as cdk from '@aws-cdk/core';
import * as s3 from '@aws-cdk/aws-s3'
import {BucketPolicy} from '@aws-cdk/aws-s3'
import {AnyPrincipal, Effect, PolicyStatement, PolicyStatementProps} from "@aws-cdk/aws-iam";
import {readFileSync} from 'fs';

export type ArnEqualsTest = "ArnEquals"

export type ArnLikeTest = "ArnLike";

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;

export enum AccessCapability {
    AdministerResource = "administer-resource",
    ReadData = "read-data",
    WriteData = "write-data",
    DeleteData = "delete-data",
}

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

    SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
        AccessCapability.AdministerResource,
        AccessCapability.ReadData,
        AccessCapability.WriteData,
        AccessCapability.DeleteData,
    );

    SUPPORTED_SERVICES = new Set<string>(["S3"]);

    _K9CapabilityMapJSON: Object = JSON.parse(readFileSync('./lib/capability_summary.json').toString());
    K9CapabilityMapByService: Map<string, Object> = new Map(Object.entries(this._K9CapabilityMapJSON));

    getAccessSpec(accessCapability: AccessCapability, desiredCapabilities: K9AccessCapabilities): K9AccessSpec {
        switch (accessCapability) {
            case "administer-resource":
                return {
                    accessCapability: accessCapability,
                    allowPrincipalArns: desiredCapabilities.allowAdministerResourceArns ? desiredCapabilities.allowAdministerResourceArns : new Set<string>(),
                    test: desiredCapabilities.allowAdministerResourceTest ? desiredCapabilities.allowAdministerResourceTest : "ArnEquals"
                };
            case "read-data":
                return {
                    accessCapability: accessCapability,
                    allowPrincipalArns: desiredCapabilities.allowReadDataArns ? desiredCapabilities.allowReadDataArns : new Set<string>(),
                    test: desiredCapabilities.allowReadDataTest ? desiredCapabilities.allowReadDataTest : "ArnEquals"
                };
            case "write-data":
                return {
                    accessCapability: accessCapability,
                    allowPrincipalArns: desiredCapabilities.allowWriteDataArns ? desiredCapabilities.allowWriteDataArns : new Set<string>(),
                    test: desiredCapabilities.allowWriteDataTest ? desiredCapabilities.allowWriteDataTest : "ArnEquals"
                };
            case "delete-data":
                return {
                    accessCapability: accessCapability,
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
        if (!this.SUPPORTED_SERVICES.has(service) && this.K9CapabilityMapByService.has(service)) {
            throw Error(`unsupported service: ${service}`)
        }

        let serviceCapabilitiesObj: Object = this.K9CapabilityMapByService.get(service) || {};
        let serviceCapabilitiesMap = new Map<string, Array<string>>(Object.entries(serviceCapabilitiesObj));

        let accessCapabilityName = accessCapabiilty.toString();
        if (serviceCapabilitiesMap &&
            serviceCapabilitiesMap.has(accessCapabilityName)) {
            return serviceCapabilitiesMap.get(accessCapabilityName) || Array<string>();
        } else {
            return new Array<string>();
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
    statement.addCondition(test, {'aws:PrincipalArn': [...arns]});
    return statement;
}

export class K9CdkStack extends cdk.Stack {
    // TODO - Remove stack definition.  We're not going to vend a stack.
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

    }
}