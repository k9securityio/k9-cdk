import * as k9policy from "../lib/k9policy";
import {AccessCapability, AccessSpec} from "../lib/k9policy";
import {AnyPrincipal} from "@aws-cdk/aws-iam";
import {stringifyStatement} from "./k9.test";

test('K9PolicyFactory#wasLikeUsed', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    expect(k9PolicyFactory.wasLikeUsed([])).toBeFalsy();
    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapability: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set<string>(),
            test: "ArnEquals"
        }
    ])).toBeFalsy();

    expect(k9PolicyFactory.wasLikeUsed([
        {
            accessCapability: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set<string>(),
            test: "ArnLike"
        }
    ])).toBeTruthy();
});

test('K9PolicyFactory#getAllowedPrincipalArns', () => {
    let k9PolicyFactory = new k9policy.K9PolicyFactory();
    let accessSpecs:Array<AccessSpec> = [
        {
            accessCapability: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set(["arn1", "arn2"]),
            test: "ArnEquals"
        },
        {
            accessCapability: AccessCapability.ReadData,
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
            accessCapability: AccessCapability.AdministerResource,
            allowPrincipalArns: new Set(adminPrincipalArns),
            test: "ArnEquals"
        },
        {
            accessCapability: AccessCapability.ReadData,
            allowPrincipalArns: new Set(readerPrincipalArns),
            test: "ArnLike"
        }

    ];
    let supportedCapabilities = [AccessCapability.AdministerResource, AccessCapability.ReadData]
    let resourceArns = ["resource_arn_1", "resource_arn_2"];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3', supportedCapabilities, accessSpecs,resourceArns);
    expect(actualPolicyStatements.length).toEqual(2);

    for(let stmt of actualPolicyStatements){
        let statementJsonStr = stringifyStatement(stmt);
        console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
        let statementObj = JSON.parse(statementJsonStr);
        if("Allow Restricted read-data" == stmt.sid){
            expect(statementObj['Resource']).toEqual(resourceArns)
            expect(statementObj['Condition']).toEqual({
                    "ArnLike": {
                        "aws:PrincipalArn": readerPrincipalArns
                    }
                }
            )
        } else if ("Allow Restricted administer-resource" == stmt.sid){
            expect(statementObj['Resource']).toEqual(resourceArns)
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
