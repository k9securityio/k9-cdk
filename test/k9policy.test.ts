import * as k9policy from "../lib/k9policy";
import {AccessCapability, AccessSpec} from "../lib/k9policy";
import {AnyPrincipal, PolicyStatement} from "@aws-cdk/aws-iam";
import {stringifyStatement} from "./helpers";

const S3_SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadConfig,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);

test('K9PolicyFactory#wasLikeUsed', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    expect(k9PolicyFactory.wasLikeUsed([])).toBeFalsy();
    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set<string>(),
            test: "ArnEquals"
        }
    ])).toBeFalsy();

    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set<string>(),
            test: "ArnLike"
        }
    ])).toBeTruthy();
});

test('K9PolicyFactory#getAllowedPrincipalArns', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let accessSpecs:Array<AccessSpec> = [
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set(["arn1", "arn2"]),
            test: "ArnEquals"
        },
        {
            accessCapabilities: AccessCapability.ReadData,
            allowPrincipalArns: new Set(["arn2", "arn3"]),
            test: "ArnLike"
        }

    ];
    expect(k9PolicyFactory.getAllowedPrincipalArns([])).toEqual(new Set<string>());
    expect(k9PolicyFactory.getAllowedPrincipalArns(accessSpecs))
        .toEqual(new Set(["arn1", "arn2", "arn3"]));
});

// noinspection JSUnusedLocalSymbols
function logStatement(stmt: PolicyStatement) {
    let statementJsonStr = stringifyStatement(stmt);
    console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
}

describe('K9PolicyFactory#makeAllowStatements', () => {
    const k9PolicyFactory = new k9policy.K9PolicyFactory();
    const adminPrincipalArns = ["arn1", "arn2"];
    const resourceArns = ["resource_arn_1", "resource_arn_2"];


    test('single access capability specs', () => {
        const readerPrincipalArns = ["arn2", "arn3"];

        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: new Set(adminPrincipalArns),
                test: "ArnEquals"
            },
            {
                accessCapabilities: AccessCapability.ReadData,
                allowPrincipalArns: new Set(readerPrincipalArns),
                test: "ArnLike"
            }

        ];
        let supportedCapabilities = [AccessCapability.AdministerResource, AccessCapability.ReadData];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
            supportedCapabilities,
            accessSpecs,
            resourceArns);
        expect(actualPolicyStatements.length).toEqual(2);

        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            if ("Allow Restricted read-data" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                        "ArnLike": {
                            "aws:PrincipalArn": readerPrincipalArns
                        }
                    }
                )
            } else if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns
                        }
                    }
                )
            } else {
                fail(`Unexpected statement ${stmt.sid}`)
            }

        }
    });

    test('mixed single and multi access capability specs', () => {
        const readWritePrincipalArns = ["arn2", "arn4"];

        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: new Set(adminPrincipalArns),
                test: "ArnEquals"
            },
            {
                accessCapabilities: new Set([AccessCapability.ReadData, AccessCapability.WriteData]),
                allowPrincipalArns: new Set(readWritePrincipalArns),
                test: "ArnLike"
            }

        ];

        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
            S3_SUPPORTED_CAPABILITIES,
            accessSpecs,
            resourceArns);

        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);

            expect(statementObj['Resource']).toEqual(resourceArns);
            if (("Allow Restricted read-data" == stmt.sid) ||
                ("Allow Restricted write-data" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                        "ArnLike": {
                            "aws:PrincipalArn": readWritePrincipalArns
                        }
                    }
                )
            } else if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns
                        }
                    }
                )
            } else {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": []
                        }
                    }
                );
            }

        }
    });

    test('multi access capability specs', () => {
        let readWritePrincipalArns = ["arn2", "arn3"];
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: new Set([AccessCapability.AdministerResource, AccessCapability.ReadConfig]),
                allowPrincipalArns: new Set(adminPrincipalArns),
                test: "ArnEquals"
            },
            {
                accessCapabilities: new Set([AccessCapability.ReadData, AccessCapability.WriteData]),
                allowPrincipalArns: new Set(readWritePrincipalArns),
                test: "ArnLike"
            }

        ];

        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
            S3_SUPPORTED_CAPABILITIES,
            accessSpecs,
            resourceArns);

        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);

            expect(statementObj['Resource']).toEqual(resourceArns);
            if (("Allow Restricted read-data" == stmt.sid) ||
                ("Allow Restricted write-data" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                        "ArnLike": {
                            "aws:PrincipalArn": readWritePrincipalArns
                        }
                    }
                )
            } else if (("Allow Restricted administer-resource" == stmt.sid) ||
                ("Allow Restricted read-config" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns
                        }
                    }
                )
            } else {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": []
                        }
                    }
                );
            }

        }
    });

    test('multiple access specs for a single capability - read-config', () => {
        let addlConfigReaders = ['_internal-tool', 'auditor', 'observability'];
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: new Set([AccessCapability.AdministerResource, AccessCapability.ReadConfig]),
                allowPrincipalArns: new Set(adminPrincipalArns),
                test: "ArnEquals"
            },

            {
                accessCapabilities: new Set([AccessCapability.ReadConfig]),
                allowPrincipalArns: new Set(addlConfigReaders),
                test: "ArnEquals"
            },
        ];

        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
            S3_SUPPORTED_CAPABILITIES,
            accessSpecs,
            resourceArns);

        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);

            expect(statementObj['Resource']).toEqual(resourceArns);
            if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns
                        }
                    }
                )
            } else if ("Allow Restricted read-config" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns.concat(addlConfigReaders).sort()
                        }
                    }
                )
            } else {
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": []
                        }
                    }
                );
            }

        }
    });

    test('throws an Error when ArnConditionTest mismatches between AccessSpecs', () => {
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: new Set(adminPrincipalArns),
                test: "ArnEquals"
            },
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: new Set("more-admin-roles*"),
                test: "ArnLike"
            }
        ];
        let supportedCapabilities = [AccessCapability.AdministerResource];

        expect(() => k9PolicyFactory.makeAllowStatements('S3',
                    supportedCapabilities,
                    accessSpecs,
                    resourceArns)).toThrow(/Cannot merge AccessSpecs; test attributes do not match/);

    });

    test('defaults ArnConditionTest to ArnEquals', () => {
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: new Set(adminPrincipalArns),
            }
        ];
        let supportedCapabilities = [AccessCapability.AdministerResource];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
            supportedCapabilities,
            accessSpecs,
            resourceArns);
        expect(actualPolicyStatements.length).toEqual(1);

        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                        "ArnEquals": {
                            "aws:PrincipalArn": adminPrincipalArns
                        }
                    }
                )
            } else {
                fail(`Unexpected statement ${stmt.sid}`)
            }
        }
    });
});

test('K9PolicyFactory#makeDenyEveryoneElsePrincipals', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let denyEveryoneElsePrincipals = k9PolicyFactory.makeDenyEveryoneElsePrincipals();
    expect(denyEveryoneElsePrincipals.length).toBeGreaterThan(1);
    const anyPrincipal = new AnyPrincipal();
    for(let principal of denyEveryoneElsePrincipals){
        expect(principal).toEqual(anyPrincipal);
        expect(principal).toBeInstanceOf(AnyPrincipal);
    }
});
