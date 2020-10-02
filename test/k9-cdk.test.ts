import {expect as expectCDK, haveResource} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import {K9AccessCapabilities, K9BucketPolicyProps} from '../lib/k9-cdk-stack';
import {Bucket} from "@aws-cdk/aws-s3/lib/bucket";

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

test('K9AccessCapabilities', () => {

    const k9AccessCapabilities: K9AccessCapabilities = {
        allowAdministerResourceArns: administerResourceArns,
        allowWriteDataArns: writeDataArns,
        allowReadDataArns: readDataArns,
        allowDeleteDataArns: deleteDataArns,
    };

    expect(k9AccessCapabilities).toEqual(k9AccessCapabilities);

    // Unit Test: k9 access capabilities
    expect(k9AccessCapabilities.allowAdministerResourceArns).toEqual(administerResourceArns);
    // expect(k9AccessCapabilities.allowAdministerResourceTest).toBe(ArnEqualsTest)
    expect(k9AccessCapabilities.allowWriteDataArns).toEqual(writeDataArns);
    expect(k9AccessCapabilities.allowReadDataArns).toEqual(readDataArns);
    expect(k9AccessCapabilities.allowDeleteDataArns).toEqual(deleteDataArns)

});

test('K9BucketPolicy', () => {
    const app = new cdk.App();

    const stack = new cdk.Stack(app, 'K9BucketPolicyTest');
    const bucket = new Bucket(stack, 'TestBucket');

    const k9AccessCapabilities: K9AccessCapabilities = {
        allowAdministerResourceArns: administerResourceArns,
        allowWriteDataArns: writeDataArns,
        allowReadDataArns: readDataArns,
        // omit delete data ARNs and 'test' configs -- use ArnEquals
    };

    const k9BucketPolicyProps: K9BucketPolicyProps = {
        bucket: bucket,
        k9AccessCapabilities: k9AccessCapabilities
    };

    // THEN
    expect(k9BucketPolicyProps.k9AccessCapabilities).toEqual(k9AccessCapabilities);

    expectCDK(stack).to(haveResource("AWS::S3::Bucket"));
});
