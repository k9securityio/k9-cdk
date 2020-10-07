#!/usr/bin/env node

import * as cdk from "@aws-cdk/core";
import * as s3 from "@aws-cdk/aws-s3";
import {K9AccessCapabilities, K9BucketPolicyProps, K9PolicyFactory} from "../lib/k9policy";

const administerResourceArns = new Set<string>([
        "arn:aws:iam::139710491120:user/ci",
        "arn:aws:iam::139710491120:user/skuenzli",
    ]
);

const writeDataArns = new Set<string>([
        "arn:aws:iam::12345678910:role/app-backend",
    ]
);
const readDataArns = new Set<string>(writeDataArns)
    .add("arn:aws:iam::12345678910:role/customer-service");

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9BucketPolicyTest');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9AccessCapabilities: K9AccessCapabilities = {
        allowAdministerResourceArns: administerResourceArns,
        allowWriteDataArns: writeDataArns,
        allowReadDataArns: readDataArns,
    };

const k9BucketPolicyProps: K9BucketPolicyProps = {
    k9AccessCapabilities: k9AccessCapabilities,
    bucket: bucket
};

const k9PolicyFactory = new K9PolicyFactory();

const bucketPolicy = k9PolicyFactory.makeBucketPolicy(stack, "S3Bucket", k9BucketPolicyProps);

console.log("bucketPolicy.document: " + JSON.stringify(bucketPolicy.document.toJSON(), null, 2));

