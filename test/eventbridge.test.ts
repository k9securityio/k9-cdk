import * as cdk from 'aws-cdk-lib/core';
import * as events from 'aws-cdk-lib/aws-events';
import { expect as expectCDK, haveResource, SynthUtils } from '@aws-cdk/assert';

import * as k9 from '../lib';
import { AccessCapability, IAccessSpec } from '../lib/k9policy';
import { SID_DENY_EVERYONE_ELSE, K9EventBridgeResourcePolicyProps } from '../src/eventbridge';

// @ts-ignore
import { stringifyPolicy } from './helpers';

const administerResourceArns = [
  'arn:aws:iam::139710491120:user/ci',
  'arn:aws:iam::139710491120:role/k9-dev-appeng',
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

describe('EventBridgeResourcePolicy', () => {
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
    const stack = new cdk.Stack(app, 'K9EventBridgeTypicalUsage', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-typical-usage');

    const ebResourcePolicyProps: K9EventBridgeResourcePolicyProps = {
      eventBus: bus,
      k9DesiredAccess: desiredAccess,
    };

    let policies = k9.eventbridge.grantAccessViaResourcePolicy(stack, 'K9Policy', ebResourcePolicyProps);
    expect(policies.length).toBeGreaterThan(0);

    expectCDK(stack).to(haveResource('AWS::Events::EventBus'));
    expectCDK(stack).to(haveResource('AWS::Events::EventBusPolicy'));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

  test('Policy Generation', () => {
    const stack = new cdk.Stack(app, 'K9EventBridgePolicyGen', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-policy-gen');

    const ebResourcePolicyProps: K9EventBridgeResourcePolicyProps = {
      eventBus: bus,
      k9DesiredAccess: desiredAccess,
    };

    let resourcePolicy = k9.eventbridge.makeResourcePolicy(ebResourcePolicyProps);
    console.log('resourcePolicy: ' + stringifyPolicy(resourcePolicy));

    expect(resourcePolicy).toBeDefined();

    let policyStr = stringifyPolicy(resourcePolicy);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj.Statement;

    expect(actualPolicyStatements).toBeDefined();

    // PascalCase SIDs (same as DynamoDB)
    const expectStmtIds = [
      SID_DENY_EVERYONE_ELSE,
      'AllowRestrictedAdministerResource',
      'AllowRestrictedReadConfig',
      'AllowRestrictedReadData',
      'AllowRestrictedWriteData',
      'AllowRestrictedDeleteData',
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

    // Verify DenyEveryoneElse structure
    const denyStmt = policyStatementMap[SID_DENY_EVERYONE_ELSE];
    expect(denyStmt.Effect).toEqual('Deny');
    expect(denyStmt.Action).toEqual('events:*');
    expect(denyStmt.Condition.Bool['aws:PrincipalIsAWSService']).toEqual(['false']);
    expect(denyStmt.Condition.ArnNotEquals['aws:PrincipalArn']).toBeDefined();

    // Verify administer-resource actions
    const adminStmt = policyStatementMap.AllowRestrictedAdministerResource;
    expect(adminStmt.Action).toContain('events:CreateEventBus');
    expect(adminStmt.Action).toContain('events:DeleteEventBus');
    expect(adminStmt.Action).toContain('events:PutPermission');
    expect(adminStmt.Action).toContain('events:TagResource');

    // Verify write-data actions
    const writeStmt = policyStatementMap.AllowRestrictedWriteData;
    expect(writeStmt.Action).toContain('events:PutEvents');
    expect(writeStmt.Action).toContain('events:PutRule');

    // Verify read-data actions
    const readStmt = policyStatementMap.AllowRestrictedReadData;
    expect(readStmt.Action).toContain('events:TestEventPattern');

    // Verify read-config actions
    const readConfigStmt = policyStatementMap.AllowRestrictedReadConfig;
    expect(readConfigStmt.Action).toContain('events:DescribeEventBus');
    expect(readConfigStmt.Action).toContain('events:ListRules');
  });

  test('grantAccessViaResourcePolicy creates individual CfnEventBusPolicy resources', () => {
    const stack = new cdk.Stack(app, 'K9EventBridgeGrantAccess', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-grant-access');

    const ebResourcePolicyProps: K9EventBridgeResourcePolicyProps = {
      eventBus: bus,
      k9DesiredAccess: desiredAccess,
    };

    let policies = k9.eventbridge.grantAccessViaResourcePolicy(stack, 'K9EB', ebResourcePolicyProps);

    // Should create one CfnEventBusPolicy per statement (5 Allow + 1 Deny = 6)
    expect(policies).toHaveLength(6);

    // Each policy should have a unique statementId
    const statementIds = policies.map(p => p.statementId);
    const uniqueIds = new Set(statementIds);
    expect(uniqueIds.size).toEqual(policies.length);
  });

  test('Validation - requires admin and read-config principals', () => {
    const stack = new cdk.Stack(app, 'K9EventBridgeValidation', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-validation');

    expect(() => {
      k9.eventbridge.makeResourcePolicy({
        eventBus: bus,
        k9DesiredAccess: [
          {
            accessCapabilities: AccessCapability.WRITE_DATA,
            allowPrincipalArns: writeDataArns,
          },
        ],
      });
    }).toThrow('At least one principal must be able to administer and read-config');
  });

  test('Unmanageable policy is rejected - admin only without read-config', () => {
    const stack = new cdk.Stack(app, 'K9EventBridgeUnmanageableAdmin', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-unmanageable-admin');

    expect(() => {
      k9.eventbridge.makeResourcePolicy({
        eventBus: bus,
        k9DesiredAccess: [
          {
            accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
            allowPrincipalArns: administerResourceArns,
          },
        ],
      });
    }).toThrow('At least one principal must be able to administer and read-config');
  });

  test('IAccessSpec with ArnLike test uses ArnNotLike in DenyEveryoneElse', () => {
    const stack = new cdk.Stack(app, 'K9EventBridgeArnLike', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-arn-like');

    const arnLikeDesiredAccess = new Array<IAccessSpec>(
      {
        accessCapabilities: [
          AccessCapability.ADMINISTER_RESOURCE,
          AccessCapability.READ_CONFIG,
        ],
        allowPrincipalArns: administerResourceArns,
        test: 'ArnLike',
      },
      {
        accessCapabilities: AccessCapability.WRITE_DATA,
        allowPrincipalArns: ['arn:aws:iam::123456789012:role/app-*'],
        test: 'ArnLike',
      },
    );

    let resourcePolicy = k9.eventbridge.makeResourcePolicy({
      eventBus: bus,
      k9DesiredAccess: arnLikeDesiredAccess,
    });

    let policyStr = stringifyPolicy(resourcePolicy);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj.Statement;

    // Find DenyEveryoneElse and verify it uses ArnNotLike
    for (let stmt of actualPolicyStatements) {
      if (stmt.Sid === SID_DENY_EVERYONE_ELSE) {
        expect(stmt.Condition.ArnNotLike).toBeDefined();
        expect(stmt.Condition.ArnNotEquals).toBeUndefined();
      }
    }
  });

});
