"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const k9policy_1 = require("../lib/k9policy");
const aws_iam_1 = require("@aws-cdk/aws-iam");
const helpers_1 = require("./helpers");
const S3_SUPPORTED_CAPABILITIES = new Array(k9policy_1.AccessCapability.AdministerResource, k9policy_1.AccessCapability.ReadConfig, k9policy_1.AccessCapability.ReadData, k9policy_1.AccessCapability.WriteData, k9policy_1.AccessCapability.DeleteData);
test('K9PolicyFactory#wasLikeUsed', () => {
    let k9PolicyFactory = new k9policy_1.K9PolicyFactory();
    expect(k9PolicyFactory.wasLikeUsed([])).toBeFalsy();
    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: [],
            test: "ArnEquals"
        }
    ])).toBeFalsy();
    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: [],
            test: "ArnLike"
        }
    ])).toBeTruthy();
});
test('K9PolicyFactory#getAllowedPrincipalArns', () => {
    let k9PolicyFactory = new k9policy_1.K9PolicyFactory();
    let accessSpecs = [
        {
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: ["arn1", "arn2"],
            test: "ArnEquals"
        },
        {
            accessCapabilities: k9policy_1.AccessCapability.ReadData,
            allowPrincipalArns: ["arn2", "arn3"],
            test: "ArnLike"
        }
    ];
    expect(k9PolicyFactory.getAllowedPrincipalArns([])).toEqual(new Set());
    expect(k9PolicyFactory.getAllowedPrincipalArns(accessSpecs))
        .toEqual(new Set(["arn1", "arn2", "arn3"]));
});
// noinspection JSUnusedLocalSymbols
function logStatement(stmt) {
    let statementJsonStr = helpers_1.stringifyStatement(stmt);
    console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
}
describe('K9PolicyFactory#makeAllowStatements', () => {
    const k9PolicyFactory = new k9policy_1.K9PolicyFactory();
    const adminPrincipalArns = ["arn1", "arn2"];
    const resourceArns = ["resource_arn_1", "resource_arn_2"];
    test('single access capability specs', () => {
        const readerPrincipalArns = ["arn2", "arn3"];
        let accessSpecs = [
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: k9policy_1.AccessCapability.ReadData,
                allowPrincipalArns: readerPrincipalArns,
                test: "ArnLike"
            }
        ];
        let supportedCapabilities = [k9policy_1.AccessCapability.AdministerResource, k9policy_1.AccessCapability.ReadData];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(2);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            if ("Allow Restricted read-data" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readerPrincipalArns
                    }
                });
            }
            else if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                });
            }
            else {
                fail(`Unexpected statement ${stmt.sid}`);
            }
        }
    });
    test('mixed single and multi access capability specs', () => {
        const readWritePrincipalArns = ["arn2", "arn4"];
        let accessSpecs = [
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: [k9policy_1.AccessCapability.ReadData, k9policy_1.AccessCapability.WriteData],
                allowPrincipalArns: readWritePrincipalArns,
                test: "ArnLike"
            }
        ];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', S3_SUPPORTED_CAPABILITIES, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            expect(statementObj['Resource']).toEqual(resourceArns);
            if (("Allow Restricted read-data" == stmt.sid) ||
                ("Allow Restricted write-data" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readWritePrincipalArns
                    }
                });
            }
            else if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                });
            }
            else {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": []
                    }
                });
            }
        }
    });
    test('multi access capability specs', () => {
        let readWritePrincipalArns = ["arn2", "arn3"];
        let accessSpecs = [
            {
                accessCapabilities: [k9policy_1.AccessCapability.AdministerResource, k9policy_1.AccessCapability.ReadConfig],
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: [k9policy_1.AccessCapability.ReadData, k9policy_1.AccessCapability.WriteData],
                allowPrincipalArns: readWritePrincipalArns,
                test: "ArnLike"
            }
        ];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', S3_SUPPORTED_CAPABILITIES, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            expect(statementObj['Resource']).toEqual(resourceArns);
            if (("Allow Restricted read-data" == stmt.sid) ||
                ("Allow Restricted write-data" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readWritePrincipalArns
                    }
                });
            }
            else if (("Allow Restricted administer-resource" == stmt.sid) ||
                ("Allow Restricted read-config" == stmt.sid)) {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                });
            }
            else {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": []
                    }
                });
            }
        }
    });
    test('multiple access specs for a single capability - read-config', () => {
        let addlConfigReaders = ['_internal-tool', 'auditor', 'observability'];
        let accessSpecs = [
            {
                accessCapabilities: [k9policy_1.AccessCapability.AdministerResource, k9policy_1.AccessCapability.ReadConfig],
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: [k9policy_1.AccessCapability.ReadConfig],
                allowPrincipalArns: addlConfigReaders,
                test: "ArnEquals"
            },
        ];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', S3_SUPPORTED_CAPABILITIES, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            expect(statementObj['Resource']).toEqual(resourceArns);
            if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                });
            }
            else if ("Allow Restricted read-config" == stmt.sid) {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns.concat(addlConfigReaders)
                    }
                });
            }
            else {
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": []
                    }
                });
            }
        }
    });
    test('throws an Error when ArnConditionTest mismatches between AccessSpecs', () => {
        let accessSpecs = [
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
                test: "ArnEquals"
            },
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: ["more-admin-roles*"],
                test: "ArnLike"
            }
        ];
        let supportedCapabilities = [k9policy_1.AccessCapability.AdministerResource];
        expect(() => k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs, resourceArns)).toThrow(/Cannot merge AccessSpecs; test attributes do not match/);
    });
    test('uses unique set of principals', () => {
        const duplicatedPrincipals = adminPrincipalArns.concat(adminPrincipalArns);
        let accessSpecs = [
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: duplicatedPrincipals,
            }
        ];
        let supportedCapabilities = [k9policy_1.AccessCapability.AdministerResource];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(1);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": Array.from(new Set(duplicatedPrincipals.values())).sort()
                    }
                });
            }
            else {
                fail(`Unexpected statement ${stmt.sid}`);
            }
        }
    });
    test('defaults ArnConditionTest to ArnEquals', () => {
        let accessSpecs = [
            {
                accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
                allowPrincipalArns: adminPrincipalArns,
            }
        ];
        let supportedCapabilities = [k9policy_1.AccessCapability.AdministerResource];
        let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs, resourceArns);
        expect(actualPolicyStatements.length).toEqual(1);
        for (let stmt of actualPolicyStatements) {
            let statementJsonStr = helpers_1.stringifyStatement(stmt);
            let statementObj = JSON.parse(statementJsonStr);
            if ("Allow Restricted administer-resource" == stmt.sid) {
                expect(statementObj['Resource']).toEqual(resourceArns);
                expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                });
            }
            else {
                fail(`Unexpected statement ${stmt.sid}`);
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
    const expectPrincipals = [
        roleDefinedDirectlyByArn,
        roleDefinedInStack,
        roleImportedFromAnotherStack
    ];
    for (let i = 0; i < 100; i++) {
        const principalsWithDuplicates = expectPrincipals.concat(...(expectPrincipals.concat().reverse()));
        const uniquePrincipals = k9policy_1.K9PolicyFactory.deduplicatePrincipals(principalsWithDuplicates);
        expect(uniquePrincipals).toEqual(expectPrincipals);
    }
});
test('K9PolicyFactory#makeDenyEveryoneElsePrincipals', () => {
    let k9PolicyFactory = new k9policy_1.K9PolicyFactory();
    let denyEveryoneElsePrincipals = k9PolicyFactory.makeDenyEveryoneElsePrincipals();
    expect(denyEveryoneElsePrincipals.length).toBeGreaterThan(1);
    const anyPrincipal = new aws_iam_1.AnyPrincipal();
    for (let principal of denyEveryoneElsePrincipals) {
        expect(principal).toEqual(anyPrincipal);
        expect(principal).toBeInstanceOf(aws_iam_1.AnyPrincipal);
    }
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiazlwb2xpY3kudGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIms5cG9saWN5LnRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSw4Q0FBOEU7QUFDOUUsOENBQStEO0FBQy9ELHVDQUE2QztBQUU3QyxNQUFNLHlCQUF5QixHQUFHLElBQUksS0FBSyxDQUN2QywyQkFBZ0IsQ0FBQyxrQkFBa0IsRUFDbkMsMkJBQWdCLENBQUMsVUFBVSxFQUMzQiwyQkFBZ0IsQ0FBQyxRQUFRLEVBQ3pCLDJCQUFnQixDQUFDLFNBQVMsRUFDMUIsMkJBQWdCLENBQUMsVUFBVSxDQUM5QixDQUFDO0FBRUYsSUFBSSxDQUFDLDZCQUE2QixFQUFFLEdBQUcsRUFBRTtJQUNyQyxJQUFJLGVBQWUsR0FBRyxJQUFJLDBCQUFlLEVBQUUsQ0FBQztJQUM1QyxNQUFNLENBQUMsZUFBZSxDQUFDLFdBQVcsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLFNBQVMsRUFBRSxDQUFDO0lBQ3BELE1BQU0sQ0FBQyxlQUFlLENBQUMsV0FBVyxDQUFDO1FBQy9CO1lBQ0ksa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsa0JBQWtCO1lBQ3ZELGtCQUFrQixFQUFFLEVBQUU7WUFDdEIsSUFBSSxFQUFFLFdBQVc7U0FDcEI7S0FDSixDQUFDLENBQUMsQ0FBQyxTQUFTLEVBQUUsQ0FBQztJQUVoQixNQUFNLENBQUMsZUFBZSxDQUFDLFdBQVcsQ0FBQztRQUMvQjtZQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtZQUN2RCxrQkFBa0IsRUFBRSxFQUFFO1lBQ3RCLElBQUksRUFBRSxTQUFTO1NBQ2xCO0tBQ0osQ0FBQyxDQUFDLENBQUMsVUFBVSxFQUFFLENBQUM7QUFDckIsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMseUNBQXlDLEVBQUUsR0FBRyxFQUFFO0lBQ2pELElBQUksZUFBZSxHQUFHLElBQUksMEJBQWUsRUFBRSxDQUFDO0lBQzVDLElBQUksV0FBVyxHQUFxQjtRQUNoQztZQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtZQUN2RCxrQkFBa0IsRUFBRSxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUM7WUFDcEMsSUFBSSxFQUFFLFdBQVc7U0FDcEI7UUFDRDtZQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLFFBQVE7WUFDN0Msa0JBQWtCLEVBQUUsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDO1lBQ3BDLElBQUksRUFBRSxTQUFTO1NBQ2xCO0tBRUosQ0FBQztJQUNGLE1BQU0sQ0FBQyxlQUFlLENBQUMsdUJBQXVCLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsSUFBSSxHQUFHLEVBQVUsQ0FBQyxDQUFDO0lBQy9FLE1BQU0sQ0FBQyxlQUFlLENBQUMsdUJBQXVCLENBQUMsV0FBVyxDQUFDLENBQUM7U0FDdkQsT0FBTyxDQUFDLElBQUksR0FBRyxDQUFTLENBQUMsTUFBTSxFQUFFLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDNUQsQ0FBQyxDQUFDLENBQUM7QUFFSCxvQ0FBb0M7QUFDcEMsU0FBUyxZQUFZLENBQUMsSUFBcUI7SUFDdkMsSUFBSSxnQkFBZ0IsR0FBRyw0QkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztJQUNoRCxPQUFPLENBQUMsR0FBRyxDQUFDLDRCQUE0QixJQUFJLFVBQVUsZ0JBQWdCLEVBQUUsQ0FBQyxDQUFDO0FBQzlFLENBQUM7QUFFRCxRQUFRLENBQUMscUNBQXFDLEVBQUUsR0FBRyxFQUFFO0lBQ2pELE1BQU0sZUFBZSxHQUFHLElBQUksMEJBQWUsRUFBRSxDQUFDO0lBQzlDLE1BQU0sa0JBQWtCLEdBQUcsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUM7SUFDNUMsTUFBTSxZQUFZLEdBQUcsQ0FBQyxnQkFBZ0IsRUFBRSxnQkFBZ0IsQ0FBQyxDQUFDO0lBRzFELElBQUksQ0FBQyxnQ0FBZ0MsRUFBRSxHQUFHLEVBQUU7UUFDeEMsTUFBTSxtQkFBbUIsR0FBRyxDQUFDLE1BQU0sRUFBRSxNQUFNLENBQUMsQ0FBQztRQUU3QyxJQUFJLFdBQVcsR0FBc0I7WUFDakM7Z0JBQ0ksa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsa0JBQWtCO2dCQUN2RCxrQkFBa0IsRUFBRSxrQkFBa0I7Z0JBQ3RDLElBQUksRUFBRSxXQUFXO2FBQ3BCO1lBQ0Q7Z0JBQ0ksa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsUUFBUTtnQkFDN0Msa0JBQWtCLEVBQUUsbUJBQW1CO2dCQUN2QyxJQUFJLEVBQUUsU0FBUzthQUNsQjtTQUVKLENBQUM7UUFDRixJQUFJLHFCQUFxQixHQUFHLENBQUMsMkJBQWdCLENBQUMsa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsUUFBUSxDQUFDLENBQUM7UUFDN0YsSUFBSSxzQkFBc0IsR0FBRyxlQUFlLENBQUMsbUJBQW1CLENBQUMsSUFBSSxFQUNqRSxxQkFBcUIsRUFDckIsV0FBVyxFQUNYLFlBQVksQ0FBQyxDQUFDO1FBQ2xCLE1BQU0sQ0FBQyxzQkFBc0IsQ0FBQyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsQ0FBQyxDQUFDLENBQUM7UUFFakQsS0FBSyxJQUFJLElBQUksSUFBSSxzQkFBc0IsRUFBRTtZQUNyQyxJQUFJLGdCQUFnQixHQUFHLDRCQUFrQixDQUFDLElBQUksQ0FBQyxDQUFDO1lBQ2hELElBQUksWUFBWSxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztZQUNoRCxJQUFJLDRCQUE0QixJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUU7Z0JBQzFDLE1BQU0sQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUM7Z0JBQ3ZELE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFNBQVMsRUFBRTt3QkFDUCxrQkFBa0IsRUFBRSxtQkFBbUI7cUJBQzFDO2lCQUNKLENBQ0osQ0FBQTthQUNKO2lCQUFNLElBQUksc0NBQXNDLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBRTtnQkFDM0QsTUFBTSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQztnQkFDdkQsTUFBTSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztvQkFDbEMsV0FBVyxFQUFFO3dCQUNULGtCQUFrQixFQUFFLGtCQUFrQjtxQkFDekM7aUJBQ0osQ0FDSixDQUFBO2FBQ0o7aUJBQU07Z0JBQ0gsSUFBSSxDQUFDLHdCQUF3QixJQUFJLENBQUMsR0FBRyxFQUFFLENBQUMsQ0FBQTthQUMzQztTQUVKO0lBQ0wsQ0FBQyxDQUFDLENBQUM7SUFFSCxJQUFJLENBQUMsZ0RBQWdELEVBQUUsR0FBRyxFQUFFO1FBQ3hELE1BQU0sc0JBQXNCLEdBQUcsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFFaEQsSUFBSSxXQUFXLEdBQXNCO1lBQ2pDO2dCQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtnQkFDdkQsa0JBQWtCLEVBQUUsa0JBQWtCO2dCQUN0QyxJQUFJLEVBQUUsV0FBVzthQUNwQjtZQUNEO2dCQUNJLGtCQUFrQixFQUFFLENBQUMsMkJBQWdCLENBQUMsUUFBUSxFQUFFLDJCQUFnQixDQUFDLFNBQVMsQ0FBQztnQkFDM0Usa0JBQWtCLEVBQUUsc0JBQXNCO2dCQUMxQyxJQUFJLEVBQUUsU0FBUzthQUNsQjtTQUVKLENBQUM7UUFFRixJQUFJLHNCQUFzQixHQUFHLGVBQWUsQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLEVBQ2pFLHlCQUF5QixFQUN6QixXQUFXLEVBQ1gsWUFBWSxDQUFDLENBQUM7UUFFbEIsTUFBTSxDQUFDLHNCQUFzQixDQUFDLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyx5QkFBeUIsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUVoRixLQUFLLElBQUksSUFBSSxJQUFJLHNCQUFzQixFQUFFO1lBQ3JDLElBQUksZ0JBQWdCLEdBQUcsNEJBQWtCLENBQUMsSUFBSSxDQUFDLENBQUM7WUFDaEQsSUFBSSxZQUFZLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1lBRWhELE1BQU0sQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUM7WUFDdkQsSUFBSSxDQUFDLDRCQUE0QixJQUFJLElBQUksQ0FBQyxHQUFHLENBQUM7Z0JBQzFDLENBQUMsNkJBQTZCLElBQUksSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFO2dCQUM3QyxNQUFNLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO29CQUNsQyxTQUFTLEVBQUU7d0JBQ1Asa0JBQWtCLEVBQUUsc0JBQXNCO3FCQUM3QztpQkFDSixDQUNKLENBQUE7YUFDSjtpQkFBTSxJQUFJLHNDQUFzQyxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUU7Z0JBQzNELE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFdBQVcsRUFBRTt3QkFDVCxrQkFBa0IsRUFBRSxrQkFBa0I7cUJBQ3pDO2lCQUNKLENBQ0osQ0FBQTthQUNKO2lCQUFNO2dCQUNILE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFdBQVcsRUFBRTt3QkFDVCxrQkFBa0IsRUFBRSxFQUFFO3FCQUN6QjtpQkFDSixDQUNKLENBQUM7YUFDTDtTQUVKO0lBQ0wsQ0FBQyxDQUFDLENBQUM7SUFFSCxJQUFJLENBQUMsK0JBQStCLEVBQUUsR0FBRyxFQUFFO1FBQ3ZDLElBQUksc0JBQXNCLEdBQUcsQ0FBQyxNQUFNLEVBQUUsTUFBTSxDQUFDLENBQUM7UUFDOUMsSUFBSSxXQUFXLEdBQXNCO1lBQ2pDO2dCQUNJLGtCQUFrQixFQUFFLENBQUMsMkJBQWdCLENBQUMsa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsVUFBVSxDQUFDO2dCQUN0RixrQkFBa0IsRUFBRSxrQkFBa0I7Z0JBQ3RDLElBQUksRUFBRSxXQUFXO2FBQ3BCO1lBQ0Q7Z0JBQ0ksa0JBQWtCLEVBQUUsQ0FBQywyQkFBZ0IsQ0FBQyxRQUFRLEVBQUUsMkJBQWdCLENBQUMsU0FBUyxDQUFDO2dCQUMzRSxrQkFBa0IsRUFBRSxzQkFBc0I7Z0JBQzFDLElBQUksRUFBRSxTQUFTO2FBQ2xCO1NBRUosQ0FBQztRQUVGLElBQUksc0JBQXNCLEdBQUcsZUFBZSxDQUFDLG1CQUFtQixDQUFDLElBQUksRUFDakUseUJBQXlCLEVBQ3pCLFdBQVcsRUFDWCxZQUFZLENBQUMsQ0FBQztRQUVsQixNQUFNLENBQUMsc0JBQXNCLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLHlCQUF5QixDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBRWhGLEtBQUssSUFBSSxJQUFJLElBQUksc0JBQXNCLEVBQUU7WUFDckMsSUFBSSxnQkFBZ0IsR0FBRyw0QkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUNoRCxJQUFJLFlBQVksR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLGdCQUFnQixDQUFDLENBQUM7WUFFaEQsTUFBTSxDQUFDLFlBQVksQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxZQUFZLENBQUMsQ0FBQztZQUN2RCxJQUFJLENBQUMsNEJBQTRCLElBQUksSUFBSSxDQUFDLEdBQUcsQ0FBQztnQkFDMUMsQ0FBQyw2QkFBNkIsSUFBSSxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUU7Z0JBQzdDLE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFNBQVMsRUFBRTt3QkFDUCxrQkFBa0IsRUFBRSxzQkFBc0I7cUJBQzdDO2lCQUNKLENBQ0osQ0FBQTthQUNKO2lCQUFNLElBQUksQ0FBQyxzQ0FBc0MsSUFBSSxJQUFJLENBQUMsR0FBRyxDQUFDO2dCQUMzRCxDQUFDLDhCQUE4QixJQUFJLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRTtnQkFDOUMsTUFBTSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztvQkFDbEMsV0FBVyxFQUFFO3dCQUNULGtCQUFrQixFQUFFLGtCQUFrQjtxQkFDekM7aUJBQ0osQ0FDSixDQUFBO2FBQ0o7aUJBQU07Z0JBQ0gsTUFBTSxDQUFDLFlBQVksQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQztvQkFDbEMsV0FBVyxFQUFFO3dCQUNULGtCQUFrQixFQUFFLEVBQUU7cUJBQ3pCO2lCQUNKLENBQ0osQ0FBQzthQUNMO1NBRUo7SUFDTCxDQUFDLENBQUMsQ0FBQztJQUVILElBQUksQ0FBQyw2REFBNkQsRUFBRSxHQUFHLEVBQUU7UUFDckUsSUFBSSxpQkFBaUIsR0FBRyxDQUFDLGdCQUFnQixFQUFFLFNBQVMsRUFBRSxlQUFlLENBQUMsQ0FBQztRQUN2RSxJQUFJLFdBQVcsR0FBc0I7WUFDakM7Z0JBQ0ksa0JBQWtCLEVBQUUsQ0FBQywyQkFBZ0IsQ0FBQyxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxVQUFVLENBQUM7Z0JBQ3RGLGtCQUFrQixFQUFFLGtCQUFrQjtnQkFDdEMsSUFBSSxFQUFFLFdBQVc7YUFDcEI7WUFFRDtnQkFDSSxrQkFBa0IsRUFBRSxDQUFDLDJCQUFnQixDQUFDLFVBQVUsQ0FBQztnQkFDakQsa0JBQWtCLEVBQUUsaUJBQWlCO2dCQUNyQyxJQUFJLEVBQUUsV0FBVzthQUNwQjtTQUNKLENBQUM7UUFFRixJQUFJLHNCQUFzQixHQUFHLGVBQWUsQ0FBQyxtQkFBbUIsQ0FBQyxJQUFJLEVBQ2pFLHlCQUF5QixFQUN6QixXQUFXLEVBQ1gsWUFBWSxDQUFDLENBQUM7UUFFbEIsTUFBTSxDQUFDLHNCQUFzQixDQUFDLE1BQU0sQ0FBQyxDQUFDLE9BQU8sQ0FBQyx5QkFBeUIsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUVoRixLQUFLLElBQUksSUFBSSxJQUFJLHNCQUFzQixFQUFFO1lBQ3JDLElBQUksZ0JBQWdCLEdBQUcsNEJBQWtCLENBQUMsSUFBSSxDQUFDLENBQUM7WUFDaEQsSUFBSSxZQUFZLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO1lBRWhELE1BQU0sQ0FBQyxZQUFZLENBQUMsVUFBVSxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsWUFBWSxDQUFDLENBQUM7WUFDdkQsSUFBSSxzQ0FBc0MsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFO2dCQUNwRCxNQUFNLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO29CQUNsQyxXQUFXLEVBQUU7d0JBQ1Qsa0JBQWtCLEVBQUUsa0JBQWtCO3FCQUN6QztpQkFDSixDQUNKLENBQUE7YUFDSjtpQkFBTSxJQUFJLDhCQUE4QixJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUU7Z0JBQ25ELE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFdBQVcsRUFBRTt3QkFDVCxrQkFBa0IsRUFBRSxrQkFBa0IsQ0FBQyxNQUFNLENBQUMsaUJBQWlCLENBQUM7cUJBQ25FO2lCQUNKLENBQ0osQ0FBQTthQUNKO2lCQUFNO2dCQUNILE1BQU0sQ0FBQyxZQUFZLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUM7b0JBQ2xDLFdBQVcsRUFBRTt3QkFDVCxrQkFBa0IsRUFBRSxFQUFFO3FCQUN6QjtpQkFDSixDQUNKLENBQUM7YUFDTDtTQUVKO0lBQ0wsQ0FBQyxDQUFDLENBQUM7SUFFSCxJQUFJLENBQUMsc0VBQXNFLEVBQUUsR0FBRyxFQUFFO1FBQzlFLElBQUksV0FBVyxHQUFzQjtZQUNqQztnQkFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7Z0JBQ3ZELGtCQUFrQixFQUFFLGtCQUFrQjtnQkFDdEMsSUFBSSxFQUFFLFdBQVc7YUFDcEI7WUFDRDtnQkFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7Z0JBQ3ZELGtCQUFrQixFQUFFLENBQUMsbUJBQW1CLENBQUM7Z0JBQ3pDLElBQUksRUFBRSxTQUFTO2FBQ2xCO1NBQ0osQ0FBQztRQUNGLElBQUkscUJBQXFCLEdBQUcsQ0FBQywyQkFBZ0IsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO1FBRWxFLE1BQU0sQ0FBQyxHQUFHLEVBQUUsQ0FBQyxlQUFlLENBQUMsbUJBQW1CLENBQUMsSUFBSSxFQUN6QyxxQkFBcUIsRUFDckIsV0FBVyxFQUNYLFlBQVksQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLHdEQUF3RCxDQUFDLENBQUM7SUFFakcsQ0FBQyxDQUFDLENBQUM7SUFFSCxJQUFJLENBQUMsK0JBQStCLEVBQUUsR0FBRyxFQUFFO1FBQ3ZDLE1BQU0sb0JBQW9CLEdBQUcsa0JBQWtCLENBQUMsTUFBTSxDQUFDLGtCQUFrQixDQUFDLENBQUM7UUFFM0UsSUFBSSxXQUFXLEdBQXNCO1lBQ2pDO2dCQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtnQkFDdkQsa0JBQWtCLEVBQUUsb0JBQW9CO2FBQzNDO1NBQ0osQ0FBQztRQUNGLElBQUkscUJBQXFCLEdBQUcsQ0FBQywyQkFBZ0IsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO1FBQ2xFLElBQUksc0JBQXNCLEdBQUcsZUFBZSxDQUFDLG1CQUFtQixDQUFDLElBQUksRUFDakUscUJBQXFCLEVBQ3JCLFdBQVcsRUFDWCxZQUFZLENBQUMsQ0FBQztRQUNsQixNQUFNLENBQUMsc0JBQXNCLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBRWpELEtBQUssSUFBSSxJQUFJLElBQUksc0JBQXNCLEVBQUU7WUFDckMsSUFBSSxnQkFBZ0IsR0FBRyw0QkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUNoRCxJQUFJLFlBQVksR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLGdCQUFnQixDQUFDLENBQUM7WUFDaEQsSUFBSSxzQ0FBc0MsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFO2dCQUNwRCxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFDO2dCQUN2RCxNQUFNLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO29CQUNsQyxXQUFXLEVBQUU7d0JBQ1Qsa0JBQWtCLEVBQUUsS0FBSyxDQUFDLElBQUksQ0FBQyxJQUFJLEdBQUcsQ0FBUyxvQkFBb0IsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLENBQUMsSUFBSSxFQUFFO3FCQUN4RjtpQkFDSixDQUNKLENBQUE7YUFDSjtpQkFBTTtnQkFDSCxJQUFJLENBQUMsd0JBQXdCLElBQUksQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFBO2FBQzNDO1NBQ0o7SUFDTCxDQUFDLENBQUMsQ0FBQztJQUVILElBQUksQ0FBQyx3Q0FBd0MsRUFBRSxHQUFHLEVBQUU7UUFDaEQsSUFBSSxXQUFXLEdBQXNCO1lBQ2pDO2dCQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtnQkFDdkQsa0JBQWtCLEVBQUUsa0JBQWtCO2FBQ3pDO1NBQ0osQ0FBQztRQUNGLElBQUkscUJBQXFCLEdBQUcsQ0FBQywyQkFBZ0IsQ0FBQyxrQkFBa0IsQ0FBQyxDQUFDO1FBQ2xFLElBQUksc0JBQXNCLEdBQUcsZUFBZSxDQUFDLG1CQUFtQixDQUFDLElBQUksRUFDakUscUJBQXFCLEVBQ3JCLFdBQVcsRUFDWCxZQUFZLENBQUMsQ0FBQztRQUNsQixNQUFNLENBQUMsc0JBQXNCLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBRWpELEtBQUssSUFBSSxJQUFJLElBQUksc0JBQXNCLEVBQUU7WUFDckMsSUFBSSxnQkFBZ0IsR0FBRyw0QkFBa0IsQ0FBQyxJQUFJLENBQUMsQ0FBQztZQUNoRCxJQUFJLFlBQVksR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLGdCQUFnQixDQUFDLENBQUM7WUFDaEQsSUFBSSxzQ0FBc0MsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFFO2dCQUNwRCxNQUFNLENBQUMsWUFBWSxDQUFDLFVBQVUsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFDO2dCQUN2RCxNQUFNLENBQUMsWUFBWSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO29CQUNsQyxXQUFXLEVBQUU7d0JBQ1Qsa0JBQWtCLEVBQUUsa0JBQWtCO3FCQUN6QztpQkFDSixDQUNKLENBQUE7YUFDSjtpQkFBTTtnQkFDSCxJQUFJLENBQUMsd0JBQXdCLElBQUksQ0FBQyxHQUFHLEVBQUUsQ0FBQyxDQUFBO2FBQzNDO1NBQ0o7SUFDTCxDQUFDLENBQUMsQ0FBQztBQUNQLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLHVDQUF1QyxFQUFFLEdBQUcsRUFBRTtJQUMvQyxNQUFNLHdCQUF3QixHQUFHLDBDQUEwQyxDQUFDO0lBRTVFLE1BQU0sa0JBQWtCLEdBQUc7UUFDdkIsWUFBWSxFQUFFO1lBQ1YsK0JBQStCO1lBQy9CLEtBQUs7U0FDUjtLQUNKLENBQUM7SUFDRixNQUFNLDRCQUE0QixHQUFHO1FBQ2pDLGlCQUFpQixFQUFFLG9FQUFvRTtLQUMxRixDQUFDO0lBRUYsTUFBTSxnQkFBZ0IsR0FBMkI7UUFDN0Msd0JBQXdCO1FBQ3hCLGtCQUFrQjtRQUNsQiw0QkFBNEI7S0FDL0IsQ0FBQztJQUdGLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUUsQ0FBQyxFQUFFLEVBQUU7UUFDMUIsTUFBTSx3QkFBd0IsR0FBMkIsZ0JBQWdCLENBQUMsTUFBTSxDQUM1RSxHQUFHLENBQUMsZ0JBQWdCLENBQUMsTUFBTSxFQUFFLENBQUMsT0FBTyxFQUFFLENBQUMsQ0FDM0MsQ0FBQztRQUVGLE1BQU0sZ0JBQWdCLEdBQTJCLDBCQUFlLENBQUMscUJBQXFCLENBQUMsd0JBQXdCLENBQUMsQ0FBQztRQUNqSCxNQUFNLENBQUMsZ0JBQWdCLENBQUMsQ0FBQyxPQUFPLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztLQUV0RDtBQUVMLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLGdEQUFnRCxFQUFFLEdBQUcsRUFBRTtJQUN4RCxJQUFJLGVBQWUsR0FBRyxJQUFJLDBCQUFlLEVBQUUsQ0FBQztJQUM1QyxJQUFJLDBCQUEwQixHQUFHLGVBQWUsQ0FBQyw4QkFBOEIsRUFBRSxDQUFDO0lBQ2xGLE1BQU0sQ0FBQywwQkFBMEIsQ0FBQyxNQUFNLENBQUMsQ0FBQyxlQUFlLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDN0QsTUFBTSxZQUFZLEdBQUcsSUFBSSxzQkFBWSxFQUFFLENBQUM7SUFDeEMsS0FBSSxJQUFJLFNBQVMsSUFBSSwwQkFBMEIsRUFBQztRQUM1QyxNQUFNLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLFlBQVksQ0FBQyxDQUFDO1FBQ3hDLE1BQU0sQ0FBQyxTQUFTLENBQUMsQ0FBQyxjQUFjLENBQUMsc0JBQVksQ0FBQyxDQUFDO0tBQ2xEO0FBQ0wsQ0FBQyxDQUFDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQge0FjY2Vzc0NhcGFiaWxpdHksIEFjY2Vzc1NwZWMsIEs5UG9saWN5RmFjdG9yeX0gZnJvbSBcIi4uL2xpYi9rOXBvbGljeVwiO1xuaW1wb3J0IHtBbnlQcmluY2lwYWwsIFBvbGljeVN0YXRlbWVudH0gZnJvbSBcIkBhd3MtY2RrL2F3cy1pYW1cIjtcbmltcG9ydCB7c3RyaW5naWZ5U3RhdGVtZW50fSBmcm9tIFwiLi9oZWxwZXJzXCI7XG5cbmNvbnN0IFMzX1NVUFBPUlRFRF9DQVBBQklMSVRJRVMgPSBuZXcgQXJyYXk8QWNjZXNzQ2FwYWJpbGl0eT4oXG4gICAgQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsXG4gICAgQWNjZXNzQ2FwYWJpbGl0eS5SZWFkQ29uZmlnLFxuICAgIEFjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGEsXG4gICAgQWNjZXNzQ2FwYWJpbGl0eS5Xcml0ZURhdGEsXG4gICAgQWNjZXNzQ2FwYWJpbGl0eS5EZWxldGVEYXRhLFxuKTtcblxudGVzdCgnSzlQb2xpY3lGYWN0b3J5I3dhc0xpa2VVc2VkJywgKCkgPT4ge1xuICAgIGxldCBrOVBvbGljeUZhY3RvcnkgPSBuZXcgSzlQb2xpY3lGYWN0b3J5KCk7XG4gICAgZXhwZWN0KGs5UG9saWN5RmFjdG9yeS53YXNMaWtlVXNlZChbXSkpLnRvQmVGYWxzeSgpO1xuICAgIGV4cGVjdChrOVBvbGljeUZhY3Rvcnkud2FzTGlrZVVzZWQoW1xuICAgICAgICB7XG4gICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBbXSxcbiAgICAgICAgICAgIHRlc3Q6IFwiQXJuRXF1YWxzXCJcbiAgICAgICAgfVxuICAgIF0pKS50b0JlRmFsc3koKTtcblxuICAgIGV4cGVjdChrOVBvbGljeUZhY3Rvcnkud2FzTGlrZVVzZWQoW1xuICAgICAgICB7XG4gICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBbXSxcbiAgICAgICAgICAgIHRlc3Q6IFwiQXJuTGlrZVwiXG4gICAgICAgIH1cbiAgICBdKSkudG9CZVRydXRoeSgpO1xufSk7XG5cbnRlc3QoJ0s5UG9saWN5RmFjdG9yeSNnZXRBbGxvd2VkUHJpbmNpcGFsQXJucycsICgpID0+IHtcbiAgICBsZXQgazlQb2xpY3lGYWN0b3J5ID0gbmV3IEs5UG9saWN5RmFjdG9yeSgpO1xuICAgIGxldCBhY2Nlc3NTcGVjczpBcnJheTxBY2Nlc3NTcGVjPiA9IFtcbiAgICAgICAge1xuICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZSxcbiAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogW1wiYXJuMVwiLCBcImFybjJcIl0sXG4gICAgICAgICAgICB0ZXN0OiBcIkFybkVxdWFsc1wiXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5SZWFkRGF0YSxcbiAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogW1wiYXJuMlwiLCBcImFybjNcIl0sXG4gICAgICAgICAgICB0ZXN0OiBcIkFybkxpa2VcIlxuICAgICAgICB9XG5cbiAgICBdO1xuICAgIGV4cGVjdChrOVBvbGljeUZhY3RvcnkuZ2V0QWxsb3dlZFByaW5jaXBhbEFybnMoW10pKS50b0VxdWFsKG5ldyBTZXQ8c3RyaW5nPigpKTtcbiAgICBleHBlY3QoazlQb2xpY3lGYWN0b3J5LmdldEFsbG93ZWRQcmluY2lwYWxBcm5zKGFjY2Vzc1NwZWNzKSlcbiAgICAgICAgLnRvRXF1YWwobmV3IFNldDxzdHJpbmc+KFtcImFybjFcIiwgXCJhcm4yXCIsIFwiYXJuM1wiXSkpO1xufSk7XG5cbi8vIG5vaW5zcGVjdGlvbiBKU1VudXNlZExvY2FsU3ltYm9sc1xuZnVuY3Rpb24gbG9nU3RhdGVtZW50KHN0bXQ6IFBvbGljeVN0YXRlbWVudCkge1xuICAgIGxldCBzdGF0ZW1lbnRKc29uU3RyID0gc3RyaW5naWZ5U3RhdGVtZW50KHN0bXQpO1xuICAgIGNvbnNvbGUubG9nKGBhY3R1YWwgcG9saWN5IHN0YXRlbWVudDogJHtzdG10fSBqc29uOiAke3N0YXRlbWVudEpzb25TdHJ9YCk7XG59XG5cbmRlc2NyaWJlKCdLOVBvbGljeUZhY3RvcnkjbWFrZUFsbG93U3RhdGVtZW50cycsICgpID0+IHtcbiAgICBjb25zdCBrOVBvbGljeUZhY3RvcnkgPSBuZXcgSzlQb2xpY3lGYWN0b3J5KCk7XG4gICAgY29uc3QgYWRtaW5QcmluY2lwYWxBcm5zID0gW1wiYXJuMVwiLCBcImFybjJcIl07XG4gICAgY29uc3QgcmVzb3VyY2VBcm5zID0gW1wicmVzb3VyY2VfYXJuXzFcIiwgXCJyZXNvdXJjZV9hcm5fMlwiXTtcblxuXG4gICAgdGVzdCgnc2luZ2xlIGFjY2VzcyBjYXBhYmlsaXR5IHNwZWNzJywgKCkgPT4ge1xuICAgICAgICBjb25zdCByZWFkZXJQcmluY2lwYWxBcm5zID0gW1wiYXJuMlwiLCBcImFybjNcIl07XG5cbiAgICAgICAgbGV0IGFjY2Vzc1NwZWNzOiBBcnJheTxBY2Nlc3NTcGVjPiA9IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5QcmluY2lwYWxBcm5zLFxuICAgICAgICAgICAgICAgIHRlc3Q6IFwiQXJuRXF1YWxzXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LlJlYWREYXRhLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogcmVhZGVyUHJpbmNpcGFsQXJucyxcbiAgICAgICAgICAgICAgICB0ZXN0OiBcIkFybkxpa2VcIlxuICAgICAgICAgICAgfVxuXG4gICAgICAgIF07XG4gICAgICAgIGxldCBzdXBwb3J0ZWRDYXBhYmlsaXRpZXMgPSBbQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsIEFjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGFdO1xuICAgICAgICBsZXQgYWN0dWFsUG9saWN5U3RhdGVtZW50cyA9IGs5UG9saWN5RmFjdG9yeS5tYWtlQWxsb3dTdGF0ZW1lbnRzKCdTMycsXG4gICAgICAgICAgICBzdXBwb3J0ZWRDYXBhYmlsaXRpZXMsXG4gICAgICAgICAgICBhY2Nlc3NTcGVjcyxcbiAgICAgICAgICAgIHJlc291cmNlQXJucyk7XG4gICAgICAgIGV4cGVjdChhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzLmxlbmd0aCkudG9FcXVhbCgyKTtcblxuICAgICAgICBmb3IgKGxldCBzdG10IG9mIGFjdHVhbFBvbGljeVN0YXRlbWVudHMpIHtcbiAgICAgICAgICAgIGxldCBzdGF0ZW1lbnRKc29uU3RyID0gc3RyaW5naWZ5U3RhdGVtZW50KHN0bXQpO1xuICAgICAgICAgICAgbGV0IHN0YXRlbWVudE9iaiA9IEpTT04ucGFyc2Uoc3RhdGVtZW50SnNvblN0cik7XG4gICAgICAgICAgICBpZiAoXCJBbGxvdyBSZXN0cmljdGVkIHJlYWQtZGF0YVwiID09IHN0bXQuc2lkKSB7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHN0YXRlbWVudE9ialsnUmVzb3VyY2UnXSkudG9FcXVhbChyZXNvdXJjZUFybnMpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuTGlrZVwiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IHJlYWRlclByaW5jaXBhbEFybnNcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoXCJBbGxvdyBSZXN0cmljdGVkIGFkbWluaXN0ZXItcmVzb3VyY2VcIiA9PSBzdG10LnNpZCkge1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ1Jlc291cmNlJ10pLnRvRXF1YWwocmVzb3VyY2VBcm5zKTtcbiAgICAgICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydDb25kaXRpb24nXSkudG9FcXVhbCh7XG4gICAgICAgICAgICAgICAgICAgICAgICBcIkFybkVxdWFsc1wiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IGFkbWluUHJpbmNpcGFsQXJuc1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBmYWlsKGBVbmV4cGVjdGVkIHN0YXRlbWVudCAke3N0bXQuc2lkfWApXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgdGVzdCgnbWl4ZWQgc2luZ2xlIGFuZCBtdWx0aSBhY2Nlc3MgY2FwYWJpbGl0eSBzcGVjcycsICgpID0+IHtcbiAgICAgICAgY29uc3QgcmVhZFdyaXRlUHJpbmNpcGFsQXJucyA9IFtcImFybjJcIiwgXCJhcm40XCJdO1xuXG4gICAgICAgIGxldCBhY2Nlc3NTcGVjczogQXJyYXk8QWNjZXNzU3BlYz4gPSBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZSxcbiAgICAgICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IGFkbWluUHJpbmNpcGFsQXJucyxcbiAgICAgICAgICAgICAgICB0ZXN0OiBcIkFybkVxdWFsc1wiXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogW0FjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGEsIEFjY2Vzc0NhcGFiaWxpdHkuV3JpdGVEYXRhXSxcbiAgICAgICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IHJlYWRXcml0ZVByaW5jaXBhbEFybnMsXG4gICAgICAgICAgICAgICAgdGVzdDogXCJBcm5MaWtlXCJcbiAgICAgICAgICAgIH1cblxuICAgICAgICBdO1xuXG4gICAgICAgIGxldCBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzID0gazlQb2xpY3lGYWN0b3J5Lm1ha2VBbGxvd1N0YXRlbWVudHMoJ1MzJyxcbiAgICAgICAgICAgIFMzX1NVUFBPUlRFRF9DQVBBQklMSVRJRVMsXG4gICAgICAgICAgICBhY2Nlc3NTcGVjcyxcbiAgICAgICAgICAgIHJlc291cmNlQXJucyk7XG5cbiAgICAgICAgZXhwZWN0KGFjdHVhbFBvbGljeVN0YXRlbWVudHMubGVuZ3RoKS50b0VxdWFsKFMzX1NVUFBPUlRFRF9DQVBBQklMSVRJRVMubGVuZ3RoKTtcblxuICAgICAgICBmb3IgKGxldCBzdG10IG9mIGFjdHVhbFBvbGljeVN0YXRlbWVudHMpIHtcbiAgICAgICAgICAgIGxldCBzdGF0ZW1lbnRKc29uU3RyID0gc3RyaW5naWZ5U3RhdGVtZW50KHN0bXQpO1xuICAgICAgICAgICAgbGV0IHN0YXRlbWVudE9iaiA9IEpTT04ucGFyc2Uoc3RhdGVtZW50SnNvblN0cik7XG5cbiAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ1Jlc291cmNlJ10pLnRvRXF1YWwocmVzb3VyY2VBcm5zKTtcbiAgICAgICAgICAgIGlmICgoXCJBbGxvdyBSZXN0cmljdGVkIHJlYWQtZGF0YVwiID09IHN0bXQuc2lkKSB8fFxuICAgICAgICAgICAgICAgIChcIkFsbG93IFJlc3RyaWN0ZWQgd3JpdGUtZGF0YVwiID09IHN0bXQuc2lkKSkge1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuTGlrZVwiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IHJlYWRXcml0ZVByaW5jaXBhbEFybnNcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIH0gZWxzZSBpZiAoXCJBbGxvdyBSZXN0cmljdGVkIGFkbWluaXN0ZXItcmVzb3VyY2VcIiA9PSBzdG10LnNpZCkge1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcImF3czpQcmluY2lwYWxBcm5cIjogYWRtaW5QcmluY2lwYWxBcm5zXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcImF3czpQcmluY2lwYWxBcm5cIjogW11cbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgdGVzdCgnbXVsdGkgYWNjZXNzIGNhcGFiaWxpdHkgc3BlY3MnLCAoKSA9PiB7XG4gICAgICAgIGxldCByZWFkV3JpdGVQcmluY2lwYWxBcm5zID0gW1wiYXJuMlwiLCBcImFybjNcIl07XG4gICAgICAgIGxldCBhY2Nlc3NTcGVjczogQXJyYXk8QWNjZXNzU3BlYz4gPSBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBbQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsIEFjY2Vzc0NhcGFiaWxpdHkuUmVhZENvbmZpZ10sXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBhZG1pblByaW5jaXBhbEFybnMsXG4gICAgICAgICAgICAgICAgdGVzdDogXCJBcm5FcXVhbHNcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IFtBY2Nlc3NDYXBhYmlsaXR5LlJlYWREYXRhLCBBY2Nlc3NDYXBhYmlsaXR5LldyaXRlRGF0YV0sXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiByZWFkV3JpdGVQcmluY2lwYWxBcm5zLFxuICAgICAgICAgICAgICAgIHRlc3Q6IFwiQXJuTGlrZVwiXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgXTtcblxuICAgICAgICBsZXQgYWN0dWFsUG9saWN5U3RhdGVtZW50cyA9IGs5UG9saWN5RmFjdG9yeS5tYWtlQWxsb3dTdGF0ZW1lbnRzKCdTMycsXG4gICAgICAgICAgICBTM19TVVBQT1JURURfQ0FQQUJJTElUSUVTLFxuICAgICAgICAgICAgYWNjZXNzU3BlY3MsXG4gICAgICAgICAgICByZXNvdXJjZUFybnMpO1xuXG4gICAgICAgIGV4cGVjdChhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzLmxlbmd0aCkudG9FcXVhbChTM19TVVBQT1JURURfQ0FQQUJJTElUSUVTLmxlbmd0aCk7XG5cbiAgICAgICAgZm9yIChsZXQgc3RtdCBvZiBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKSB7XG4gICAgICAgICAgICBsZXQgc3RhdGVtZW50SnNvblN0ciA9IHN0cmluZ2lmeVN0YXRlbWVudChzdG10KTtcbiAgICAgICAgICAgIGxldCBzdGF0ZW1lbnRPYmogPSBKU09OLnBhcnNlKHN0YXRlbWVudEpzb25TdHIpO1xuXG4gICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydSZXNvdXJjZSddKS50b0VxdWFsKHJlc291cmNlQXJucyk7XG4gICAgICAgICAgICBpZiAoKFwiQWxsb3cgUmVzdHJpY3RlZCByZWFkLWRhdGFcIiA9PSBzdG10LnNpZCkgfHxcbiAgICAgICAgICAgICAgICAoXCJBbGxvdyBSZXN0cmljdGVkIHdyaXRlLWRhdGFcIiA9PSBzdG10LnNpZCkpIHtcbiAgICAgICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydDb25kaXRpb24nXSkudG9FcXVhbCh7XG4gICAgICAgICAgICAgICAgICAgICAgICBcIkFybkxpa2VcIjoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIFwiYXdzOlByaW5jaXBhbEFyblwiOiByZWFkV3JpdGVQcmluY2lwYWxBcm5zXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB9IGVsc2UgaWYgKChcIkFsbG93IFJlc3RyaWN0ZWQgYWRtaW5pc3Rlci1yZXNvdXJjZVwiID09IHN0bXQuc2lkKSB8fFxuICAgICAgICAgICAgICAgIChcIkFsbG93IFJlc3RyaWN0ZWQgcmVhZC1jb25maWdcIiA9PSBzdG10LnNpZCkpIHtcbiAgICAgICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydDb25kaXRpb24nXSkudG9FcXVhbCh7XG4gICAgICAgICAgICAgICAgICAgICAgICBcIkFybkVxdWFsc1wiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IGFkbWluUHJpbmNpcGFsQXJuc1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydDb25kaXRpb24nXSkudG9FcXVhbCh7XG4gICAgICAgICAgICAgICAgICAgICAgICBcIkFybkVxdWFsc1wiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IFtdXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgIHRlc3QoJ211bHRpcGxlIGFjY2VzcyBzcGVjcyBmb3IgYSBzaW5nbGUgY2FwYWJpbGl0eSAtIHJlYWQtY29uZmlnJywgKCkgPT4ge1xuICAgICAgICBsZXQgYWRkbENvbmZpZ1JlYWRlcnMgPSBbJ19pbnRlcm5hbC10b29sJywgJ2F1ZGl0b3InLCAnb2JzZXJ2YWJpbGl0eSddO1xuICAgICAgICBsZXQgYWNjZXNzU3BlY3M6IEFycmF5PEFjY2Vzc1NwZWM+ID0gW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogW0FjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLCBBY2Nlc3NDYXBhYmlsaXR5LlJlYWRDb25maWddLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5QcmluY2lwYWxBcm5zLFxuICAgICAgICAgICAgICAgIHRlc3Q6IFwiQXJuRXF1YWxzXCJcbiAgICAgICAgICAgIH0sXG5cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IFtBY2Nlc3NDYXBhYmlsaXR5LlJlYWRDb25maWddLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRkbENvbmZpZ1JlYWRlcnMsXG4gICAgICAgICAgICAgICAgdGVzdDogXCJBcm5FcXVhbHNcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgXTtcblxuICAgICAgICBsZXQgYWN0dWFsUG9saWN5U3RhdGVtZW50cyA9IGs5UG9saWN5RmFjdG9yeS5tYWtlQWxsb3dTdGF0ZW1lbnRzKCdTMycsXG4gICAgICAgICAgICBTM19TVVBQT1JURURfQ0FQQUJJTElUSUVTLFxuICAgICAgICAgICAgYWNjZXNzU3BlY3MsXG4gICAgICAgICAgICByZXNvdXJjZUFybnMpO1xuXG4gICAgICAgIGV4cGVjdChhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzLmxlbmd0aCkudG9FcXVhbChTM19TVVBQT1JURURfQ0FQQUJJTElUSUVTLmxlbmd0aCk7XG5cbiAgICAgICAgZm9yIChsZXQgc3RtdCBvZiBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKSB7XG4gICAgICAgICAgICBsZXQgc3RhdGVtZW50SnNvblN0ciA9IHN0cmluZ2lmeVN0YXRlbWVudChzdG10KTtcbiAgICAgICAgICAgIGxldCBzdGF0ZW1lbnRPYmogPSBKU09OLnBhcnNlKHN0YXRlbWVudEpzb25TdHIpO1xuXG4gICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydSZXNvdXJjZSddKS50b0VxdWFsKHJlc291cmNlQXJucyk7XG4gICAgICAgICAgICBpZiAoXCJBbGxvdyBSZXN0cmljdGVkIGFkbWluaXN0ZXItcmVzb3VyY2VcIiA9PSBzdG10LnNpZCkge1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcImF3czpQcmluY2lwYWxBcm5cIjogYWRtaW5QcmluY2lwYWxBcm5zXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB9IGVsc2UgaWYgKFwiQWxsb3cgUmVzdHJpY3RlZCByZWFkLWNvbmZpZ1wiID09IHN0bXQuc2lkKSB7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHN0YXRlbWVudE9ialsnQ29uZGl0aW9uJ10pLnRvRXF1YWwoe1xuICAgICAgICAgICAgICAgICAgICAgICAgXCJBcm5FcXVhbHNcIjoge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIFwiYXdzOlByaW5jaXBhbEFyblwiOiBhZG1pblByaW5jaXBhbEFybnMuY29uY2F0KGFkZGxDb25maWdSZWFkZXJzKVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgKVxuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICBleHBlY3Qoc3RhdGVtZW50T2JqWydDb25kaXRpb24nXSkudG9FcXVhbCh7XG4gICAgICAgICAgICAgICAgICAgICAgICBcIkFybkVxdWFsc1wiOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgXCJhd3M6UHJpbmNpcGFsQXJuXCI6IFtdXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cbiAgICB9KTtcblxuICAgIHRlc3QoJ3Rocm93cyBhbiBFcnJvciB3aGVuIEFybkNvbmRpdGlvblRlc3QgbWlzbWF0Y2hlcyBiZXR3ZWVuIEFjY2Vzc1NwZWNzJywgKCkgPT4ge1xuICAgICAgICBsZXQgYWNjZXNzU3BlY3M6IEFycmF5PEFjY2Vzc1NwZWM+ID0gW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBhZG1pblByaW5jaXBhbEFybnMsXG4gICAgICAgICAgICAgICAgdGVzdDogXCJBcm5FcXVhbHNcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogW1wibW9yZS1hZG1pbi1yb2xlcypcIl0sXG4gICAgICAgICAgICAgICAgdGVzdDogXCJBcm5MaWtlXCJcbiAgICAgICAgICAgIH1cbiAgICAgICAgXTtcbiAgICAgICAgbGV0IHN1cHBvcnRlZENhcGFiaWxpdGllcyA9IFtBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZV07XG5cbiAgICAgICAgZXhwZWN0KCgpID0+IGs5UG9saWN5RmFjdG9yeS5tYWtlQWxsb3dTdGF0ZW1lbnRzKCdTMycsXG4gICAgICAgICAgICAgICAgICAgIHN1cHBvcnRlZENhcGFiaWxpdGllcyxcbiAgICAgICAgICAgICAgICAgICAgYWNjZXNzU3BlY3MsXG4gICAgICAgICAgICAgICAgICAgIHJlc291cmNlQXJucykpLnRvVGhyb3coL0Nhbm5vdCBtZXJnZSBBY2Nlc3NTcGVjczsgdGVzdCBhdHRyaWJ1dGVzIGRvIG5vdCBtYXRjaC8pO1xuXG4gICAgfSk7XG5cbiAgICB0ZXN0KCd1c2VzIHVuaXF1ZSBzZXQgb2YgcHJpbmNpcGFscycsICgpID0+IHtcbiAgICAgICAgY29uc3QgZHVwbGljYXRlZFByaW5jaXBhbHMgPSBhZG1pblByaW5jaXBhbEFybnMuY29uY2F0KGFkbWluUHJpbmNpcGFsQXJucyk7XG4gICAgICAgIFxuICAgICAgICBsZXQgYWNjZXNzU3BlY3M6IEFycmF5PEFjY2Vzc1NwZWM+ID0gW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBkdXBsaWNhdGVkUHJpbmNpcGFscyxcbiAgICAgICAgICAgIH1cbiAgICAgICAgXTtcbiAgICAgICAgbGV0IHN1cHBvcnRlZENhcGFiaWxpdGllcyA9IFtBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZV07XG4gICAgICAgIGxldCBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzID0gazlQb2xpY3lGYWN0b3J5Lm1ha2VBbGxvd1N0YXRlbWVudHMoJ1MzJyxcbiAgICAgICAgICAgIHN1cHBvcnRlZENhcGFiaWxpdGllcyxcbiAgICAgICAgICAgIGFjY2Vzc1NwZWNzLFxuICAgICAgICAgICAgcmVzb3VyY2VBcm5zKTtcbiAgICAgICAgZXhwZWN0KGFjdHVhbFBvbGljeVN0YXRlbWVudHMubGVuZ3RoKS50b0VxdWFsKDEpO1xuXG4gICAgICAgIGZvciAobGV0IHN0bXQgb2YgYWN0dWFsUG9saWN5U3RhdGVtZW50cykge1xuICAgICAgICAgICAgbGV0IHN0YXRlbWVudEpzb25TdHIgPSBzdHJpbmdpZnlTdGF0ZW1lbnQoc3RtdCk7XG4gICAgICAgICAgICBsZXQgc3RhdGVtZW50T2JqID0gSlNPTi5wYXJzZShzdGF0ZW1lbnRKc29uU3RyKTtcbiAgICAgICAgICAgIGlmIChcIkFsbG93IFJlc3RyaWN0ZWQgYWRtaW5pc3Rlci1yZXNvdXJjZVwiID09IHN0bXQuc2lkKSB7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHN0YXRlbWVudE9ialsnUmVzb3VyY2UnXSkudG9FcXVhbChyZXNvdXJjZUFybnMpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcImF3czpQcmluY2lwYWxBcm5cIjogQXJyYXkuZnJvbShuZXcgU2V0PHN0cmluZz4oZHVwbGljYXRlZFByaW5jaXBhbHMudmFsdWVzKCkpKS5zb3J0KClcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIClcbiAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgZmFpbChgVW5leHBlY3RlZCBzdGF0ZW1lbnQgJHtzdG10LnNpZH1gKVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG4gICAgXG4gICAgdGVzdCgnZGVmYXVsdHMgQXJuQ29uZGl0aW9uVGVzdCB0byBBcm5FcXVhbHMnLCAoKSA9PiB7XG4gICAgICAgIGxldCBhY2Nlc3NTcGVjczogQXJyYXk8QWNjZXNzU3BlYz4gPSBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZSxcbiAgICAgICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IGFkbWluUHJpbmNpcGFsQXJucyxcbiAgICAgICAgICAgIH1cbiAgICAgICAgXTtcbiAgICAgICAgbGV0IHN1cHBvcnRlZENhcGFiaWxpdGllcyA9IFtBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZV07XG4gICAgICAgIGxldCBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzID0gazlQb2xpY3lGYWN0b3J5Lm1ha2VBbGxvd1N0YXRlbWVudHMoJ1MzJyxcbiAgICAgICAgICAgIHN1cHBvcnRlZENhcGFiaWxpdGllcyxcbiAgICAgICAgICAgIGFjY2Vzc1NwZWNzLFxuICAgICAgICAgICAgcmVzb3VyY2VBcm5zKTtcbiAgICAgICAgZXhwZWN0KGFjdHVhbFBvbGljeVN0YXRlbWVudHMubGVuZ3RoKS50b0VxdWFsKDEpO1xuXG4gICAgICAgIGZvciAobGV0IHN0bXQgb2YgYWN0dWFsUG9saWN5U3RhdGVtZW50cykge1xuICAgICAgICAgICAgbGV0IHN0YXRlbWVudEpzb25TdHIgPSBzdHJpbmdpZnlTdGF0ZW1lbnQoc3RtdCk7XG4gICAgICAgICAgICBsZXQgc3RhdGVtZW50T2JqID0gSlNPTi5wYXJzZShzdGF0ZW1lbnRKc29uU3RyKTtcbiAgICAgICAgICAgIGlmIChcIkFsbG93IFJlc3RyaWN0ZWQgYWRtaW5pc3Rlci1yZXNvdXJjZVwiID09IHN0bXQuc2lkKSB7XG4gICAgICAgICAgICAgICAgZXhwZWN0KHN0YXRlbWVudE9ialsnUmVzb3VyY2UnXSkudG9FcXVhbChyZXNvdXJjZUFybnMpO1xuICAgICAgICAgICAgICAgIGV4cGVjdChzdGF0ZW1lbnRPYmpbJ0NvbmRpdGlvbiddKS50b0VxdWFsKHtcbiAgICAgICAgICAgICAgICAgICAgICAgIFwiQXJuRXF1YWxzXCI6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBcImF3czpQcmluY2lwYWxBcm5cIjogYWRtaW5QcmluY2lwYWxBcm5zXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICApXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIGZhaWwoYFVuZXhwZWN0ZWQgc3RhdGVtZW50ICR7c3RtdC5zaWR9YClcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pO1xufSk7XG5cbnRlc3QoJ0s5UG9saWN5RmFjdG9yeSNkZWR1cGxpY2F0ZVByaW5jaXBhbHMnLCAoKSA9PiB7XG4gICAgY29uc3Qgcm9sZURlZmluZWREaXJlY3RseUJ5QXJuID0gXCJhcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnJvbGUvc29tZS1yb2xlXCI7XG5cbiAgICBjb25zdCByb2xlRGVmaW5lZEluU3RhY2sgPSB7XG4gICAgICAgIFwiRm46OkdldEF0dFwiOiBbXG4gICAgICAgICAgICBcInNvbWVBdXRvR2VuZXJhdGVkUm9sZUU5MDYyQTlDXCIsXG4gICAgICAgICAgICBcIkFyblwiLFxuICAgICAgICBdLFxuICAgIH07XG4gICAgY29uc3Qgcm9sZUltcG9ydGVkRnJvbUFub3RoZXJTdGFjayA9IHtcbiAgICAgICAgXCJGbjo6SW1wb3J0VmFsdWVcIjogXCJzb21lLXNoYXJlZC1zdGFjazpFeHBvcnRzT3V0cHV0Rm5HZXRBdHRTb21lUm9sZThERkEwMTgxQXJuNDNFQzZFMEJcIixcbiAgICB9O1xuXG4gICAgY29uc3QgZXhwZWN0UHJpbmNpcGFsczogQXJyYXk8c3RyaW5nIHwgb2JqZWN0PiA9IFtcbiAgICAgICAgcm9sZURlZmluZWREaXJlY3RseUJ5QXJuLFxuICAgICAgICByb2xlRGVmaW5lZEluU3RhY2ssXG4gICAgICAgIHJvbGVJbXBvcnRlZEZyb21Bbm90aGVyU3RhY2tcbiAgICBdO1xuXG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IDEwMDsgaSsrKSB7XG4gICAgICAgIGNvbnN0IHByaW5jaXBhbHNXaXRoRHVwbGljYXRlczogQXJyYXk8c3RyaW5nIHwgb2JqZWN0PiA9IGV4cGVjdFByaW5jaXBhbHMuY29uY2F0KFxuICAgICAgICAgICAgLi4uKGV4cGVjdFByaW5jaXBhbHMuY29uY2F0KCkucmV2ZXJzZSgpKVxuICAgICAgICApO1xuXG4gICAgICAgIGNvbnN0IHVuaXF1ZVByaW5jaXBhbHM6IEFycmF5PHN0cmluZyB8IG9iamVjdD4gPSBLOVBvbGljeUZhY3RvcnkuZGVkdXBsaWNhdGVQcmluY2lwYWxzKHByaW5jaXBhbHNXaXRoRHVwbGljYXRlcyk7XG4gICAgICAgIGV4cGVjdCh1bmlxdWVQcmluY2lwYWxzKS50b0VxdWFsKGV4cGVjdFByaW5jaXBhbHMpO1xuXG4gICAgfVxuXG59KTtcblxudGVzdCgnSzlQb2xpY3lGYWN0b3J5I21ha2VEZW55RXZlcnlvbmVFbHNlUHJpbmNpcGFscycsICgpID0+IHtcbiAgICBsZXQgazlQb2xpY3lGYWN0b3J5ID0gbmV3IEs5UG9saWN5RmFjdG9yeSgpO1xuICAgIGxldCBkZW55RXZlcnlvbmVFbHNlUHJpbmNpcGFscyA9IGs5UG9saWN5RmFjdG9yeS5tYWtlRGVueUV2ZXJ5b25lRWxzZVByaW5jaXBhbHMoKTtcbiAgICBleHBlY3QoZGVueUV2ZXJ5b25lRWxzZVByaW5jaXBhbHMubGVuZ3RoKS50b0JlR3JlYXRlclRoYW4oMSk7XG4gICAgY29uc3QgYW55UHJpbmNpcGFsID0gbmV3IEFueVByaW5jaXBhbCgpO1xuICAgIGZvcihsZXQgcHJpbmNpcGFsIG9mIGRlbnlFdmVyeW9uZUVsc2VQcmluY2lwYWxzKXtcbiAgICAgICAgZXhwZWN0KHByaW5jaXBhbCkudG9FcXVhbChhbnlQcmluY2lwYWwpO1xuICAgICAgICBleHBlY3QocHJpbmNpcGFsKS50b0JlSW5zdGFuY2VPZihBbnlQcmluY2lwYWwpO1xuICAgIH1cbn0pO1xuIl19