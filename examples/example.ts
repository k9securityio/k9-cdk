#!/usr/bin/env node
import {writeFileSync} from 'fs';
import * as cdk from "@aws-cdk/core";
import * as s3 from "@aws-cdk/aws-s3";
import * as k9 from "../lib"; //change to from "@k9securityio/k9-cdk";

const administerResourceArns = new Set<string>([
        "arn:aws:iam::12345678910:user/ci",
        "arn:aws:iam::12345678910:user/person1",
    ]
);

const writeDataArns = new Set<string>([
        "arn:aws:iam::12345678910:role/app-backend",
    ]
);
const readDataArns = new Set<string>(writeDataArns)
    .add("arn:aws:iam::12345678910:role/customer-service");

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9Example');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<k9.k9policy.AccessSpec>(
        {
            accessCapability: k9.k9policy.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        },
        {
            accessCapability: k9.k9policy.AccessCapability.WriteData,
            allowPrincipalArns: writeDataArns,
        },
        {
            accessCapability: k9.k9policy.AccessCapability.ReadData,
            allowPrincipalArns: readDataArns,
        }
        // omit access spec for delete-data because it is unneeded
    )
};

const bucketPolicy = k9.s3.makeBucketPolicy(stack, "S3Bucket", k9BucketPolicyProps);
writeFileSync('generated.bucket-policy.json',
    JSON.stringify(bucketPolicy.document.toJSON(), null, 2));
