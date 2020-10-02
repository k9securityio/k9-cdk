import * as cdk from '@aws-cdk/core';
import {BucketPolicy, BucketPolicyProps} from "@aws-cdk/aws-s3";

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

export interface K9BucketPolicyProps extends BucketPolicyProps {
    readonly k9AccessCapabilities: K9AccessCapabilities
}


export class K9BucketPolicy extends BucketPolicy {
    constructor(scope: cdk.Construct, id: string, props: K9BucketPolicyProps) {
        super(scope, id, props);
    }
}

export class K9CdkStack extends cdk.Stack {
    // TODO - Remove stack definition.  We're not going to vend a stack.
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // The code that defines your stack goes here
    }
}