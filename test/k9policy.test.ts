import {AccessCapability, AccessSpec, K9PolicyFactory} from "../lib/k9policy";
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
    let k9PolicyFactory = new K9PolicyFactory();
    expect(k9PolicyFactory.wasLikeUsed([])).toBeFalsy();
    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: [],
            test: "ArnEquals"
        }
    ])).toBeFalsy();

    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: [],
            test: "ArnLike"
        }
    ])).toBeTruthy();
});

test('K9PolicyFactory#getAllowedPrincipalArns', () => {
    let k9PolicyFactory = new K9PolicyFactory();
    let accessSpecs:Array<AccessSpec> = [
        {
            accessCapabilities: AccessCapability.AdministerResource,
            allowPrincipalArns: ["arn1", "arn2"],
            test: "ArnEquals"
        },
        {
            accessCapabilities: AccessCapability.ReadData,
            allowPrincipalArns: ["arn2", "arn3"],
            test: "ArnLike"
        }

    ];
    expect(k9PolicyFactory.getAllowedPrincipalArns([])).toEqual(new Set<string>());
    expect(k9PolicyFactory.getAllowedPrincipalArns(accessSpecs))
        .toEqual(new Set<string>(["arn1", "arn2", "arn3"]));
});

// noinspection JSUnusedLocalSymbols
function logStatement(stmt: PolicyStatement) {
    let statementJsonStr = stringifyStatement(stmt);
    console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
}

describe('K9PolicyFactory#makeAllowStatements', () => {
    const k9PolicyFactory = new K9PolicyFactory();
    const adminPrincipalArns = ["arn1", "arn2"];
    const resourceArns = ["resource_arn_1", "resource_arn_2"];


    test('single access capability specs', () => {
        const readerPrincipalArns = ["arn2", "arn3"];

        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: AccessCapability.ReadData,
                allowPrincipalArns: readerPrincipalArns,
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
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: [AccessCapability.ReadData, AccessCapability.WriteData],
                allowPrincipalArns: readWritePrincipalArns,
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
                accessCapabilities: [AccessCapability.AdministerResource, AccessCapability.ReadConfig],
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: [AccessCapability.ReadData, AccessCapability.WriteData],
                allowPrincipalArns: readWritePrincipalArns,
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
                accessCapabilities: [AccessCapability.AdministerResource, AccessCapability.ReadConfig],
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },

            {
                accessCapabilities: [AccessCapability.ReadConfig],
                allowPrincipalArns: addlConfigReaders,
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
                            "aws:PrincipalArn": adminPrincipalArns.concat(addlConfigReaders)
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
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: ["more-admin-roles*"],
                test: "ArnLike"
            }
        ];
        let supportedCapabilities = [AccessCapability.AdministerResource];

        expect(() => k9PolicyFactory.makeAllowStatements('S3',
                    supportedCapabilities,
                    accessSpecs,
                    resourceArns)).toThrow(/Cannot merge AccessSpecs; test attributes do not match/);

    });

    test('uses unique set of principals', () => {
        const duplicatedPrincipals = adminPrincipalArns.concat(adminPrincipalArns);
        
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: duplicatedPrincipals,
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
                            "aws:PrincipalArn": Array.from(new Set<string>(duplicatedPrincipals.values())).sort()
                        }
                    }
                )
            } else {
                fail(`Unexpected statement ${stmt.sid}`)
            }
        }
    });
    
    test('defaults ArnConditionTest to ArnEquals', () => {
        let accessSpecs: Array<AccessSpec> = [
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
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

test('K9PolicyFactory#deduplicatePrincipals', () => {
    const roleDefinedDirectlyByArn = "arn:aws:iam::123456789012:role/some-role";

    const roleDefinedInStack = {
        "Fn::GetAtt": [
            "someAutoGeneratedRoleE9062A9C",
            "Arn",
        ],
    };
    const roleImportedFromAnotherStack = {
        "Fn::ImportValue": "some-shared-stack:ExportsOutputFnGetAttSomeRole8DFA0181Arn43EC6E0B",
    };

    const expectPrincipals: Array<string | object> = [
        roleDefinedDirectlyByArn,
        roleDefinedInStack,
        roleImportedFromAnotherStack
    ];


    for (let i = 0; i < 100; i++) {
        const principalsWithDuplicates: Array<string | object> = expectPrincipals.concat(
            ...(expectPrincipals.concat().reverse())
        );

        const uniquePrincipals: Array<string | object> = K9PolicyFactory.deduplicatePrincipals(principalsWithDuplicates);
        expect(uniquePrincipals).toEqual(expectPrincipals);

    }

});

test('K9PolicyFactory#makeDenyEveryoneElsePrincipals', () => {
    let k9PolicyFactory = new K9PolicyFactory();
    let denyEveryoneElsePrincipals = k9PolicyFactory.makeDenyEveryoneElsePrincipals();
    expect(denyEveryoneElsePrincipals.length).toBeGreaterThan(1);
    const anyPrincipal = new AnyPrincipal();
    for(let principal of denyEveryoneElsePrincipals){
        expect(principal).toEqual(anyPrincipal);
        expect(principal).toBeInstanceOf(AnyPrincipal);
    }
});
