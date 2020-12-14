import {expect as expectCDK, haveResource, SynthUtils} from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as s3 from '@aws-cdk/aws-s3';
import {AccessCapability, AccessSpec} from '../lib/k9policy';
import {K9BucketPolicyProps} from "../lib/s3";
import * as k9 from "../lib";

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
    const bucketPolicy = k9.s3.makeBucketPolicy(stack, "S3Bucket", k9BucketPolicyProps);

    console.log("bucketPolicy.document: " + JSON.stringify(bucketPolicy.document.toJSON(), null, 2));

    expectCDK(stack).to(haveResource("AWS::S3::Bucket"));
    expectCDK(stack).to(haveResource("AWS::S3::BucketPolicy"));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});
