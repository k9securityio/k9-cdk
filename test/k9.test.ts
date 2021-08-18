import {expect as expectCDK, haveResource, SynthUtils} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy} from '@aws-cdk/core';
import * as kms from '@aws-cdk/aws-kms';
import * as s3 from '@aws-cdk/aws-s3';
import {AccessCapability, AccessSpec} from '../lib/k9policy';
import {K9BucketPolicyProps} from "../lib/s3";
import {K9KeyPolicyProps} from "../lib/kms";
import * as k9 from "../lib";
import {AddToResourcePolicyResult, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";

// Test the primary public interface to k9 cdk

const administerResourceArns = new Set<string>([
        "arn:aws:iam::139710491120:user/ci",
    ]
);

const writeDataArns = new Set<string>([
        "arn:aws:iam::12345678910:role/app-backend",
    ]
);
const readDataArns = new Set<string>(writeDataArns)
    .add("arn:aws:iam::12345678910:role/customer-service");

const deleteDataArns = new Set<string>([
        "arn:aws:iam::139710491120:user/super-admin",
    ]
);

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9PolicyTest');

test('K9BucketPolicy', () => {

    const bucket = new s3.Bucket(stack, 'TestBucket', {});

    const k9BucketPolicyProps: K9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array<AccessSpec>(
            {
                accessCapability: AccessCapability.AdministerResource,
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapability: AccessCapability.WriteData,
                allowPrincipalArns: writeDataArns,
            },
            {
                accessCapability: AccessCapability.ReadData,
                allowPrincipalArns: readDataArns,
            },
            {
                accessCapability: AccessCapability.DeleteData,
                allowPrincipalArns: deleteDataArns,
            },
        )
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();

    console.log("bucket.policy?.document: " + stringifyPolicy(bucket.policy?.document));
    expect(bucket.policy?.document).toBeDefined();

    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);

    expectCDK(stack).to(haveResource("AWS::S3::Bucket"));
    expectCDK(stack).to(haveResource("AWS::S3::BucketPolicy"));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});

test('k9.s3.grantAccessViaResourcePolicy merges permissions for autoDeleteObjects', () => {

    const bucket = new s3.Bucket(stack, 'AutoDeleteBucket', {
        autoDeleteObjects: true,
        removalPolicy: RemovalPolicy.DESTROY
    });

    let originalBucketPolicy = bucket.policy;
    expect(originalBucketPolicy).toBeTruthy();
    console.log("original bucketPolicy.document: " + stringifyPolicy(bucket?.policy?.document));

    const k9BucketPolicyProps: K9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array<AccessSpec>(
            {
                accessCapability: AccessCapability.AdministerResource,
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapability: AccessCapability.DeleteData,
                allowPrincipalArns: deleteDataArns,
            },
        )
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "AutoDeleteBucket", k9BucketPolicyProps);

    expect(bucket.policy).toStrictEqual(originalBucketPolicy);
    
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    
    console.log("k9 bucket policy: " + stringifyPolicy(bucket.policy?.document));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});

test('K9KeyPolicy', () => {

    const k9KeyPolicyProps: K9KeyPolicyProps = {
        k9DesiredAccess: new Array<AccessSpec>(
            {
                accessCapability: AccessCapability.AdministerResource,
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapability: AccessCapability.WriteData,
                allowPrincipalArns: writeDataArns,
            },
            {
                accessCapability: AccessCapability.ReadData,
                allowPrincipalArns: readDataArns,
            },
            {
                accessCapability: AccessCapability.DeleteData,
                allowPrincipalArns: deleteDataArns,
            },
        )
    };
    const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

    console.log("keyPolicy.document: " + stringifyPolicy(keyPolicy));

    new kms.Key(stack, 'TestKey', {policy: keyPolicy});

    expectCDK(stack).to(haveResource("AWS::KMS::Key"));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});

function assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults: AddToResourcePolicyResult[]) {
    expect(addToResourcePolicyResults.length).toEqual(9);
    for (let result of addToResourcePolicyResults) {
        expect(result.statementAdded).toBeTruthy();
    }
}

export function stringifyPolicy(policyDocument?: PolicyDocument) {
    if(policyDocument){
        return JSON.stringify(policyDocument.toJSON(), null, 2);
    } else {
        return "<none>"
    }
}

export function stringifyStatement(policyStatement?: PolicyStatement) {
    if(policyStatement){
        return JSON.stringify(policyStatement.toStatementJson(), null, 2);
    } else {
        return "<none>"
    }
}