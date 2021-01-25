import {Effect, PolicyStatement, PolicyStatementProps} from "@aws-cdk/aws-iam";
import {readFileSync} from 'fs';

export type ArnEqualsTest = "ArnEquals"

export type ArnLikeTest = "ArnLike";

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;

export enum AccessCapability {
    AdministerResource = "administer-resource",
    ReadConfig = "read-config",
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

    SUPPORTED_SERVICES = new Set<string>([
        "S3",
        "KMS",
    ]);
    _K9CapabilityMapJSON: Object = JSON.parse(readFileSync(`${__dirname}/capability_summary.json`).toString());
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

    makeAllowStatements(serviceName: string,
                        supportedCapabilities: Array<AccessCapability>,
                        desiredAccess: Array<AccessSpec>,
                        resourceArns: Array<string>): Array<PolicyStatement> {
        let policyStatements = new Array<PolicyStatement>();
        let accessSpecsByCapability: Map<AccessCapability, AccessSpec> = new Map<AccessCapability, AccessSpec>();
        desiredAccess.forEach(accessSpec => accessSpecsByCapability.set(accessSpec.accessCapability, accessSpec));

        for (let supportedCapability of supportedCapabilities) {
            let accessSpec: AccessSpec = accessSpecsByCapability.get(supportedCapability) ||
                { //generate a default access spec if none was provided
                    accessCapability: supportedCapability,
                    allowPrincipalArns: new Set<string>(),
                    test: "ArnEquals"
                }
            ;
            let arnConditionTest = accessSpec.test || "ArnEquals";

            let statement = this.makeAllowStatement(`Allow Restricted ${supportedCapability}`,
                this.getActions(serviceName, supportedCapability),
                accessSpec.allowPrincipalArns,
                arnConditionTest,
                resourceArns);
            policyStatements.push(statement);
        }
        return policyStatements;
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

    wasLikeUsed(accessSpecs: AccessSpec[]): boolean {
        for (let accessSpec of accessSpecs) {
            if ("ArnLike" == accessSpec.test) {
                return true;
            }
        }
        return false;
    }

    getAllowedPrincipalArns(accessSpecs: AccessSpec[]): Set<string> {
        let allowedPrincipalArns = new Set<string>();
        for (let accessSpec of accessSpecs) {
            accessSpec.allowPrincipalArns.forEach(function (value) {
                allowedPrincipalArns.add(value);
            });
        }
        return allowedPrincipalArns;
    }

}
