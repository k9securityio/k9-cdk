import * as iam from "@aws-cdk/aws-iam";
import {AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";
import * as cdk from "@aws-cdk/core";

export interface K9KeyPolicyProps {
    readonly k9DesiredAccess: Array<AccessSpec>
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
    AccessCapability.AdministerResource,
    AccessCapability.ReadConfig,
    AccessCapability.ReadData,
    AccessCapability.WriteData,
    AccessCapability.DeleteData,
);


export function makeKeyPolicy(scope: cdk.Construct, id: string, props: K9KeyPolicyProps): PolicyDocument {
    const policyFactory = new K9PolicyFactory();
    const policy = new iam.PolicyDocument();

    const resourceArns = ['*'];

    const allowStatements = policyFactory.makeAllowStatements("KMS",
        SUPPORTED_CAPABILITIES,
        props.k9DesiredAccess,
        resourceArns);
    policy.addStatements(...allowStatements);

    const denyEveryoneElseStatement = new PolicyStatement({
        sid: 'DenyEveryoneElse',
        effect: Effect.DENY,
        principals: [new AccountRootPrincipal()],
        actions: ['kms:*'],
        resources: resourceArns
    });
    const denyEveryoneElseTest = policyFactory.wasLikeUsed(props.k9DesiredAccess) ?
        'ArnNotLike' :
        'ArnNotEquals';
    const allAllowedPrincipalArns = policyFactory.getAllowedPrincipalArns(props.k9DesiredAccess);
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
