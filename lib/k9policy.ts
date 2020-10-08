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

export interface AccessSpec {
    accessCapability: AccessCapability
    allowPrincipalArns: Set<string>
    test?: ArnConditionTest
}

export class K9PolicyFactory {

    SUPPORTED_SERVICES = new Set<string>(["S3"]);

    _K9CapabilityMapJSON: Object = JSON.parse(readFileSync('./lib/capability_summary.json').toString());
    K9CapabilityMapByService: Map<string, Object> = new Map(Object.entries(this._K9CapabilityMapJSON));
    
    getActions(service: string, accessCapability: AccessCapability): Array<string> {
        if (!this.SUPPORTED_SERVICES.has(service) && this.K9CapabilityMapByService.has(service)) {
            throw Error(`unsupported service: ${service}`)
        }

        let serviceCapabilitiesObj: Object = this.K9CapabilityMapByService.get(service) || {};
        let serviceCapabilitiesMap = new Map<string, Array<string>>(Object.entries(serviceCapabilitiesObj));

        let accessCapabilityName = accessCapability.toString();
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