#!/usr/bin/env node

import * as cdk from "@aws-cdk/core";
import * as s3 from "@aws-cdk/aws-s3";
import {AccessCapability, K9AccessSpec} from "../lib/k9policy";
import * as k9 from "../lib";

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

const stack = new cdk.Stack(app, 'K9PolicyLibIntegrationTest');
const bucket = new s3.Bucket(stack, 'TestBucket', {});

const k9BucketPolicyProps: k9.s3.K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<K9AccessSpec>(
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
        }
    )
};

k9.s3.makeBucketPolicy(stack, "S3Bucket", k9BucketPolicyProps);
