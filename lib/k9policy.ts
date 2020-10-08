import {Effect, PolicyStatement, PolicyStatementProps} from "@aws-cdk/aws-iam";
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

}

export class K9PolicyFactory {

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

    getActions(service: string, accessCapabiilty: AccessCapability): Array<string> {
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

    makeAllowStatement(sid: string,
                       actions: Array<string>,
                       principalArns: Set<string>,
                       test: ArnConditionTest,
                       resources: Array<string>): PolicyStatement {
        let policyStatementProps: PolicyStatementProps = {
            sid: sid,
            effect: Effect.ALLOW
        };
        let statement = new PolicyStatement(policyStatementProps);
        statement.addActions(...actions);
        statement.addAnyPrincipal();
        statement.addResources(...resources);
        statement.addCondition(test, {'aws:PrincipalArn': [...principalArns]});
        return statement;
    }
}