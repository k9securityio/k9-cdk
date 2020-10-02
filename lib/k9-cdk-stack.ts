import * as cdk from '@aws-cdk/core';
import * as s3 from '@aws-cdk/aws-s3'
import {BucketPolicy} from '@aws-cdk/aws-s3'
import {AnyPrincipal, Effect, PolicyStatement} from "@aws-cdk/aws-iam";

export type ArnEqualsTest = {
    value: "ArnEquals";
};

export type ArnLikeTest = {
    value: "ArnLike";
};

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;

export class K9AccessCapabilities {

    constructor(
        readonly allowAdministerResourceArns?: Set<string>,
        readonly allowAdministerResourceTest?: ArnConditionTest,
        readonly allowReadDataArns?: Set<string>,
        readonly allowReadDataTest?: ArnConditionTest,
        readonly allowWriteDataArns?: Set<string>,
        readonly allowWriteDataTest?: ArnConditionTest,
        readonly allowDeleteDataArns?: Set<string>,
        readonly allowDeleteDataTest?: ArnConditionTest,
    ) {

    }

    // ??? Add support for custom actions
    // will probably encourage users to create custom statements directly using the policy instead of trying to model
}

export interface K9BucketPolicyProps extends s3.BucketPolicyProps {
    readonly k9AccessCapabilities: K9AccessCapabilities
    readonly bucket: s3.Bucket
}

export class K9PolicyFactory {

    makeBucketPolicy(scope: cdk.Construct, id: string, props: K9BucketPolicyProps): BucketPolicy {

        const policy = new s3.BucketPolicy(scope, `${id}Policy`, {bucket: props.bucket});

        let arns = props.k9AccessCapabilities.allowAdministerResourceArns;
        if (arns) {
            console.log("arns: " + arns.values());
            let statement = makeAllowStatement(arns, ["s3:GetBucketPolicy"]);
            policy.document.addStatements(statement)
        } else {
            console.log("no arns")
        }

        policy.document.addStatements(new PolicyStatement({
                effect: Effect.DENY,
                principals: [new AnyPrincipal()],
                actions: ['*'],
                resources: [`${props.bucket.bucketArn}/*`],
                conditions: {
                    Bool: {'aws:SecureTransport': false},
                },
            })
        );

        policy.document.validateForResourcePolicy();
        console.log("validated resource policy");

        return policy
    }
}

function makeAllowStatement(arns: Set<string>, actions: Array<string>) {
    let statement = new PolicyStatement();
    for (let arn of arns) {
        console.log(arn);
        statement.addActions(...actions);
        statement.effect = Effect.ALLOW;
        statement.addArnPrincipal(arn);
        statement.addAllResources();
    }
    return statement;
}

export class K9CdkStack extends cdk.Stack {
    // TODO - Remove stack definition.  We're not going to vend a stack.
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

    }
}