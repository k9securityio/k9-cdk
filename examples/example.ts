#!/usr/bin/env node
import {writeFileSync} from 'fs';
import * as cdk from "aws-cdk-lib";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as kms from "aws-cdk-lib/aws-kms";
import * as k9 from "@k9securityio/k9-cdk";

const administerResourceArns = [
    "arn:aws:iam::123456789012:user/ci",
    "arn:aws:iam::123456789012:user/person1",
];

const readConfigArns = administerResourceArns.concat([
    "arn:aws:iam::123456789012:role/k9-auditor"
]);

const writeDataArns = [
    "arn:aws:iam::123456789012:role/app-backend",
];
const readDataArns = writeDataArns.concat([
    "arn:aws:iam::123456789012:role/customer-service"
]);

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9Example');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_CONFIG,
            allowPrincipalArns: readConfigArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
            allowPrincipalArns: writeDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_DATA,
            allowPrincipalArns: readDataArns,
        }
        // omit access spec for delete-data because it is unneeded
    )
};

k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);
writeFileSync('generated.bucket-policy.json',
    JSON.stringify(bucket.policy?.document.toJSON(), null, 2));


const keyPolicyProps: k9.kms.K9KeyPolicyProps = {
    k9DesiredAccess: new Array<k9.k9policy.IAccessSpec>(
        {
            accessCapabilities: [
                k9.k9policy.AccessCapability.ADMINISTER_RESOURCE,
                k9.k9policy.AccessCapability.READ_CONFIG
            ],
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.WRITE_DATA,
            allowPrincipalArns: writeDataArns,
        },
        {
            accessCapabilities: k9.k9policy.AccessCapability.READ_DATA,
            allowPrincipalArns: readDataArns,
        }
        // omit access spec for delete-data because it is unneeded
    )

};
const keyPolicy = k9.kms.makeKeyPolicy(keyPolicyProps);

writeFileSync('generated.key-policy.json',
    JSON.stringify(keyPolicy.toJSON(), null, 2));

new kms.Key(stack, 'TestKey', {policy: keyPolicy});

app.synth();
