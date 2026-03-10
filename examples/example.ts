#!/usr/bin/env node
import {writeFileSync} from 'fs';
import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as events from "aws-cdk-lib/aws-events";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as k9 from "@k9securityio/k9-cdk";

const administerResourceArns = [
    "arn:aws:iam::123456789012:user/ci",
    "arn:aws:iam::123456789012:user/person1",
];

const readConfigArns = administerResourceArns.concat([
    "arn:aws:iam::123456789012:role/k9-auditor",
    "arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer",
]);

const writeDataArns = [
    "arn:aws:iam::123456789012:role/app-backend",
];
const readDataArns = writeDataArns.concat([
    "arn:aws:iam::123456789012:role/customer-service"
]);

const app = new cdk.App();

const stack = new cdk.Stack(app, 'K9Example');

// demonstrate generating a k9 bucket policy
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


// demonstrate generating a k9 queue policy
const queue = new sqs.Queue(stack, 'TestQueue', {
    queueName: 'app-queue-with-k9-policy',
});

const k9QueuePolicyProps: k9.sqs.K9SQSResourcePolicyProps = {
    queue: queue,
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
}
k9.sqs.grantAccessViaResourcePolicy(k9QueuePolicyProps);
// unfortunately, the Queue object doesn't make the queue policy readable; re-generate for example policy file
writeFileSync('generated.queue-policy.json',
    JSON.stringify(k9.sqs.makeResourcePolicy(k9QueuePolicyProps).toJSON(), null, 2));


// demonstrate generating a k9 key policy
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

// demonstrate generating a k9 DynamoDB policy
const ddbResourcePolicyProps: k9.dynamodb.K9DynamoDBResourcePolicyProps = {
    k9DesiredAccess: k9BucketPolicyProps.k9DesiredAccess
};

const ddbResourcePolicy = k9.dynamodb.makeResourcePolicy(ddbResourcePolicyProps);

writeFileSync('generated.dynamodb-policy.json',
    JSON.stringify(ddbResourcePolicy.toJSON(), null, 2));

new dynamodb.TableV2(stack, 'TestTable', {
  partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
  resourcePolicy: ddbResourcePolicy,
});

// demonstrate generating a k9 EventBridge bus policy
const bus = new events.EventBus(stack, 'TestBus', {
    eventBusName: 'app-bus-with-k9-policy',
});

const k9EventBusPolicyProps: k9.events.K9EventBusResourcePolicyProps = {
    bus: bus,
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
        }
        // EventBridge does not support read-data or delete-data capabilities
    )
};

k9.events.grantAccessViaResourcePolicy(k9EventBusPolicyProps);
writeFileSync('generated.eventbus-policy.json',
    JSON.stringify(k9.events.makeResourcePolicy(k9EventBusPolicyProps).toJSON(), null, 2));

app.synth();
