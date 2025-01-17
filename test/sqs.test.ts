import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cdk from 'aws-cdk-lib/core';

import * as k9 from '../lib';
import { AccessCapability, IAccessSpec } from '../lib/k9policy';
import { SID_DENY_EVERYONE_ELSE } from '../lib/sqs';
import { K9SQSResourcePolicyProps } from '../src/sqs';

// @ts-ignore
import { stringifyPolicy } from './helpers';

const administerResourceArns = [
  'arn:aws:iam::139710491120:user/ci',
];

const writeDataArns = [
  'arn:aws:iam::123456789012:role/app-backend',
];

const readDataArns = writeDataArns.concat(
  ['arn:aws:iam::123456789012:role/customer-service'],
);

const deleteDataArns = [
  'arn:aws:iam::139710491120:user/super-admin',
];

const app = new cdk.App();


describe('SQSResourcePolicy', () => {
  const desiredAccess = new Array<IAccessSpec>(
    {
      accessCapabilities: [
        AccessCapability.ADMINISTER_RESOURCE,
        AccessCapability.READ_CONFIG,
      ],
      allowPrincipalArns: administerResourceArns,
    },
    {
      accessCapabilities: AccessCapability.WRITE_DATA,
      allowPrincipalArns: writeDataArns,
    },
    {
      accessCapabilities: AccessCapability.READ_DATA,
      allowPrincipalArns: readDataArns,
    },
    {
      accessCapabilities: AccessCapability.DELETE_DATA,
      allowPrincipalArns: deleteDataArns,
    },
  );

  test('Typical usage', () => {
    const stack = new cdk.Stack(app, 'K9SQSResourcePolicyTestTypicalUsage', { env: { region: 'us-east-1' } });

    const sqsResourcePolicyProps: K9SQSResourcePolicyProps = {
      k9DesiredAccess: desiredAccess,
    };

    let resourcePolicy = k9.sqs.makeResourcePolicy(sqsResourcePolicyProps);
    console.log('resourcePolicy: ' + stringifyPolicy(resourcePolicy));

    expect(resourcePolicy).toBeDefined();

    let policyStr = stringifyPolicy(resourcePolicy);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj.Statement;

    expect(actualPolicyStatements).toBeDefined();

    const expectStmtIds = [
      SID_DENY_EVERYONE_ELSE,
      'Allow Restricted administer-resource',
      'Allow Restricted read-config',
      'Allow Restricted read-data',
      'Allow Restricted write-data',
      'Allow Restricted delete-data',
    ];
    expect(actualPolicyStatements).toHaveLength(expectStmtIds.length);

    const policyStatementMap: { [key: string]: any } = {};
    for (let stmt of actualPolicyStatements) {
      if (stmt.Sid) {
        policyStatementMap[stmt.Sid] = stmt;
      }
    }

    for (let expectStmtId of expectStmtIds) {
      expect(policyStatementMap[expectStmtId]).toBeTruthy();
    }

    const queue = new sqs.Queue(stack, 'test-queue-typical-usage');

    for (let stmt of actualPolicyStatements) {
      queue.addToResourcePolicy(stmt);
    }

    console.log('queue: ' + queue);
    // console.log('queue.policy: ' + stringifyPolicy(queue.policy));

    // expectCDK(stack).to(haveResource('AWS::SQS::Queue'));
    // expectCDK(stack).to(haveResource('AWS::SQS::QueuePolicy'));
    // expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

});
