import * as iam from "@aws-cdk/aws-iam";
import {AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";

export interface K9KeyPolicyProps {
    readonly k9DesiredAccess: Array<AccessSpec>
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);


export function makeKeyPolicy(scope: cdk.Construct, id: string, props: K9KeyPolicyProps): PolicyDocument {
    const policyFactory = new K9PolicyFactory();
    const policy = new iam.PolicyDocument();

    let resourceArns = [
        `*`
    ];

    let allAllowedPrincipalArns = new Set<string>();
    let wasArnLikeTestUsed = false;

    let accessSpecsByCapability: Map<AccessCapability, AccessSpec> = new Map<AccessCapability, AccessSpec>();

    props.k9DesiredAccess.forEach(accessSpec => accessSpecsByCapability.set(accessSpec.accessCapability, accessSpec));

    for (let supportedCapability of SUPPORTED_CAPABILITIES) {
        let accessSpec: AccessSpec = accessSpecsByCapability.get(supportedCapability) ||
            { //generate a default access spec if none was provided
                accessCapability: supportedCapability,
                allowPrincipalArns: new Set<string>(),
                test: "ArnEquals"
            }
        ;
        let arnConditionTest = accessSpec.test || "ArnEquals";
        if (arnConditionTest == "ArnLike") {
            wasArnLikeTestUsed = true;
        }

        let statement = policyFactory.makeAllowStatement(`Restricted-${supportedCapability}`,
            policyFactory.getActions('KMS', supportedCapability),
            accessSpec.allowPrincipalArns,
            arnConditionTest,
            resourceArns);
        policy.addStatements(statement);

        accessSpec.allowPrincipalArns.forEach(function (value) {
            allAllowedPrincipalArns.add(value);
        });
    }

    const denyEveryoneElseTest = policyFactory.wasLikeUsed(props.k9DesiredAccess) ?
        'ArnNotLike' :
        'ArnNotEquals';
    let denyEveryoneElseStatement = new PolicyStatement({
        sid: 'DenyEveryoneElse',
        effect: Effect.DENY,
        principals: [new AccountRootPrincipal()],
        actions: ['kms:*'],
        resources: resourceArns
    });
    denyEveryoneElseStatement.addCondition(denyEveryoneElseTest, {
        'aws:PrincipalArn': [...allAllowedPrincipalArns]
    });

    policy.addStatements(
        new PolicyStatement({
            sid: 'AllowRootUserToAdministerKey',
            effect: Effect.ALLOW,
            principals: [new AccountRootPrincipal()],
            actions: ['kms:*'],
            resources: resourceArns,
        }),
        denyEveryoneElseStatement,
    );

    policy.validateForResourcePolicy();

    return policy;
}
