import * as k9policy from "../lib/k9policy";
import {AccessCapability, AccessSpec} from "../lib/k9policy";
import {AnyPrincipal} from "@aws-cdk/aws-iam";
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

test('K9PolicyFactory#makeAllowStatements - single access capability spec', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let adminPrincipalArns = ["arn1", "arn2"];
    let readerPrincipalArns = ["arn2", "arn3"];
    let accessSpecs:Array<AccessSpec> = [
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
    let resourceArns = ["resource_arn_1", "resource_arn_2"];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs,resourceArns);
    expect(actualPolicyStatements.length).toEqual(2);

    for(let stmt of actualPolicyStatements){
        let statementJsonStr = stringifyStatement(stmt);
        console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
        let statementObj = JSON.parse(statementJsonStr);
        if("Allow Restricted read-data" == stmt.sid){
            expect(statementObj['Resource']).toEqual(resourceArns);
            expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readerPrincipalArns
                    }
                }
            )
        } else if ("Allow Restricted administer-resource" == stmt.sid){
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
})

test('K9PolicyFactory#makeAllowStatements - mixed access capability spec', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let adminPrincipalArns = ["arn1", "arn2"];
    let readWritePrincipalArns = ["arn2", "arn3"];
    let accessSpecs:Array<AccessSpec> = [
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

    let resourceArns = ["resource_arn_1", "resource_arn_2"];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
        S3_SUPPORTED_CAPABILITIES,
        accessSpecs,
        resourceArns);

    expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

    for(let stmt of actualPolicyStatements){
        let statementJsonStr = stringifyStatement(stmt);
        console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
        let statementObj = JSON.parse(statementJsonStr);

        expect(statementObj['Resource']).toEqual(resourceArns);
        if(("Allow Restricted read-data" == stmt.sid) ||
            ("Allow Restricted write-data" == stmt.sid)){
            expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readWritePrincipalArns
                    }
                }
            )
        } else if ("Allow Restricted administer-resource" == stmt.sid){
            expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": adminPrincipalArns
                    }
                }
            )
        } else {
            //fail(`Unexpected statement ${stmt.sid}`)
            expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": []
                    }
                }
            );
        }

    }
});

test('K9PolicyFactory#makeAllowStatements - multi access capability spec', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let adminPrincipalArns = ["arn1", "arn2"];
    let readWritePrincipalArns = ["arn2", "arn3"];
    let accessSpecs:Array<AccessSpec> = [
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

    let resourceArns = ["resource_arn_1", "resource_arn_2"];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
        S3_SUPPORTED_CAPABILITIES,
        accessSpecs,
        resourceArns);

    expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

    for(let stmt of actualPolicyStatements){
        let statementJsonStr = stringifyStatement(stmt);
        console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
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
            //fail(`Unexpected statement ${stmt.sid}`)
            expect(statementObj['Condition']).toEqual({
                    "ArnEquals": {
                        "aws:PrincipalArn": []
                    }
                }
            );
        }

    }
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
