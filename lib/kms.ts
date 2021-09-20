import * as iam from "@aws-cdk/aws-iam";
import {AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";
import {AccessCapability, AccessSpec, K9PolicyFactory} from "./k9policy";

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


export function makeKeyPolicy(props: K9KeyPolicyProps): PolicyDocument {
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
        principals: policyFactory.makeDenyEveryoneElsePrincipals(),
        actions: ['kms:*'],
        resources: resourceArns
    });
    denyEveryoneElseStatement.addCondition('Bool', {
        'aws:PrincipalIsAWSService': ["false"]
    });
    const denyEveryoneElseTest = policyFactory.wasLikeUsed(props.k9DesiredAccess) ?
        'ArnNotLike' :
        'ArnNotEquals';
    const allAllowedPrincipalArns = policyFactory.getAllowedPrincipalArns(props.k9DesiredAccess);
    const accountRootPrincipal = new AccountRootPrincipal();
    denyEveryoneElseStatement.addCondition(denyEveryoneElseTest, {
        'aws:PrincipalArn': [
            // Place Root Principal arn in stable, prominent position;
            // will render as an object Fn::Join'ing Partition & AccountId
            accountRootPrincipal.arn,
            ...allAllowedPrincipalArns
        ]
    });

    policy.addStatements(
        new PolicyStatement({
            sid: 'AllowRootUserToAdministerKey',
            effect: Effect.ALLOW,
            principals: [accountRootPrincipal],
            actions: ['kms:*'],
            resources: resourceArns,
        }),
        denyEveryoneElseStatement,
    );

    policy.validateForResourcePolicy();

    return policy;
}
