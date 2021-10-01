import {expect as expectCDK, haveResource, SynthUtils} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import {RemovalPolicy} from '@aws-cdk/core';
import * as kms from '@aws-cdk/aws-kms';
import * as s3 from '@aws-cdk/aws-s3';
import {AccessCapability, AccessSpec} from '../lib/k9policy';
import {K9BucketPolicyProps} from "../lib/s3";
import {K9KeyPolicyProps, SID_ALLOW_ROOT_AND_IDENTITY_POLICIES, SID_DENY_EVERYONE_ELSE} from "../lib/kms";
import * as k9 from "../lib";
import {AddToResourcePolicyResult} from "@aws-cdk/aws-iam";
import {stringifyPolicy} from "./helpers";

// Test the primary public interface to k9 cdk

const administerResourceArns = [
    "arn:aws:iam::139710491120:user/ci",
];

const writeDataArns = [
    "arn:aws:iam::123456789012:role/app-backend",
];

const readDataArns = writeDataArns.concat(
    ["arn:aws:iam::123456789012:role/customer-service"]
);

const deleteDataArns = [
    "arn:aws:iam::139710491120:user/super-admin",
];

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9PolicyTest');

test('K9BucketPolicy', () => {

    const bucket = new s3.Bucket(stack, 'TestBucket', {});

    const k9BucketPolicyProps: K9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array<AccessSpec>(
            {
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapabilities: AccessCapability.WriteData,
                allowPrincipalArns: writeDataArns,
            },
            {
                accessCapabilities: AccessCapability.ReadData,
                allowPrincipalArns: readDataArns,
            },
            {
                accessCapabilities: AccessCapability.DeleteData,
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

test('K9BucketPolicy - AccessSpec with set of capabilities', () => {
    const localstack = new cdk.Stack(app, 'K9BucketPolicyMultiAccessCapa');
    const bucket = new s3.Bucket(localstack, 'TestBucketWithMultiAccessSpec', {});

    const k9BucketPolicyProps: K9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array<AccessSpec>(
            {
                accessCapabilities: [
                    AccessCapability.AdministerResource,
                    AccessCapability.ReadConfig
                ],
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapabilities: [
                    AccessCapability.ReadData,
                    AccessCapability.WriteData,
                    AccessCapability.DeleteData,
                ],
                allowPrincipalArns: writeDataArns,
            },
        )
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(localstack, "S3BucketMultiAccessSpec", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();

    console.log("bucket.policy?.document: " + stringifyPolicy(bucket.policy?.document));
    expect(bucket.policy?.document).toBeDefined();

    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);

    expectCDK(localstack).to(haveResource("AWS::S3::Bucket"));
    expectCDK(localstack).to(haveResource("AWS::S3::BucketPolicy"));
    expect(SynthUtils.toCloudFormation(localstack)).toMatchSnapshot();
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
                accessCapabilities: AccessCapability.AdministerResource,
                allowPrincipalArns: administerResourceArns,
            },
            {
                accessCapabilities: AccessCapability.DeleteData,
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

describe('K9KeyPolicy', () => {
    const desiredAccess = new Array<AccessSpec>(
        {
            accessCapabilities: [
                AccessCapability.AdministerResource,
                AccessCapability.ReadConfig
            ],
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: AccessCapability.WriteData,
            allowPrincipalArns: writeDataArns,
        },
        {
            accessCapabilities: AccessCapability.ReadData,
            allowPrincipalArns: readDataArns,
        },
        {
            accessCapabilities: AccessCapability.DeleteData,
            allowPrincipalArns: deleteDataArns,
        },
    );
    test('Without Allow root user and Identity policies', () => {
        const k9KeyPolicyProps: K9KeyPolicyProps = {
            k9DesiredAccess: desiredAccess
        };

        expect(k9KeyPolicyProps.trustAccountIdentities).toBeFalsy();
        const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

        let policyJsonStr = stringifyPolicy(keyPolicy);
        console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
        let policyObj = JSON.parse(policyJsonStr);

        let actualPolicyStatements = policyObj['Statement'];
        expect(actualPolicyStatements).toBeDefined();

        let denyEveryoneElseStmt: any;
        let allowRootStmt: any;
        for (let stmt of actualPolicyStatements) {
            if(SID_DENY_EVERYONE_ELSE == stmt.Sid){
                denyEveryoneElseStmt = stmt;
            } else if(SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid){
                allowRootStmt = stmt;
            }
        }

        expect(denyEveryoneElseStmt).toBeFalsy();
        expect(allowRootStmt).toBeFalsy();

        new kms.Key(stack, 'TestKeyNoRoot', {policy: keyPolicy});

        expectCDK(stack).to(haveResource("AWS::KMS::Key"));
        expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
    });
    
    test('Allow root user and Identity policies', () => {

        const k9KeyPolicyProps: K9KeyPolicyProps = {
            k9DesiredAccess: desiredAccess,
            trustAccountIdentities: true
        };
        
        expect(k9KeyPolicyProps.trustAccountIdentities).toBeTruthy();
        const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

        let policyJsonStr = stringifyPolicy(keyPolicy);
        console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
        let policyObj = JSON.parse(policyJsonStr);

        let actualPolicyStatements = policyObj['Statement'];
        expect(actualPolicyStatements).toBeDefined();

        let denyEveryoneElseStmt: any;
        let allowRootStmt: any;
        for (let stmt of actualPolicyStatements) {
            if(SID_DENY_EVERYONE_ELSE == stmt.Sid){
                denyEveryoneElseStmt = stmt;
            } else if(SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid){
                allowRootStmt = stmt;
            }
        }

        expect(denyEveryoneElseStmt).toBeTruthy();
        expect(allowRootStmt).toBeTruthy();


        new kms.Key(stack, 'TestKeyAllowRoot', {policy: keyPolicy});

        expectCDK(stack).to(haveResource("AWS::KMS::Key"));
        expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
    });

    test('Unmanageable key policy is rejected', () => {

        const unmanageableCapabilityCombos = [
          [],
          [AccessCapability.AdministerResource],
          [AccessCapability.ReadConfig],
          [AccessCapability.AdministerResource, AccessCapability.WriteData]
        ];

        for(let trustAccountIdentities of [true, false]){
            for(let unmanageableAccessCapabilities of unmanageableCapabilityCombos){
                let desiredAccess = new Array<AccessSpec>(
                    {
                        accessCapabilities: unmanageableAccessCapabilities,
                        allowPrincipalArns: administerResourceArns,
                    },
                );

                let k9KeyPolicyProps: K9KeyPolicyProps = {
                    k9DesiredAccess: desiredAccess,
                    trustAccountIdentities: true
                };

                expect(() => k9.kms.makeKeyPolicy(k9KeyPolicyProps))
                    .toThrow(/At least one principal must be able to administer and read-config for keys/)

            }

        }
    });

});

function assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults: AddToResourcePolicyResult[]) {
    expect(addToResourcePolicyResults.length).toEqual(9);
    for (let result of addToResourcePolicyResults) {
        expect(result.statementAdded).toBeTruthy();
    }
}
