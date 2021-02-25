import * as k9policy from "../lib/k9policy";
import {AccessCapability, AccessSpec} from "../lib/k9policy";
import {AnyPrincipal} from "@aws-cdk/aws-iam";

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
