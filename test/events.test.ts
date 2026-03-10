import * as cdk from 'aws-cdk-lib/core';
import * as events from 'aws-cdk-lib/aws-events';
import { expect as expectCDK, haveResource, SynthUtils } from '@aws-cdk/assert';

import * as k9 from '../lib';
import { AccessCapability, IAccessSpec, SID_DENY_UNTRUSTED_ORGS } from '../lib/k9policy';
import { SID_DENY_EVERYONE_ELSE } from '../lib/events';
import { K9EventBusResourcePolicyProps } from '../src/events';

// @ts-ignore
import { stringifyPolicy } from './helpers';

const administerResourceArns = [
  'arn:aws:iam::139710491120:role/ci',
  'arn:aws:iam::139710491120:role/k9-dev-appeng',
];

const writeDataArns = [
  'arn:aws:iam::123456789012:role/app-backend',
];

const app = new cdk.App();


describe('EventBusResourcePolicy', () => {
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
  );

  test('Typical usage — specific principals, no org constraint', () => {
    const stack = new cdk.Stack(app, 'K9EventBusTypicalUsage', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-typical-usage');

    const eventBusResourcePolicyProps: K9EventBusResourcePolicyProps = {
      bus: bus,
      k9DesiredAccess: desiredAccess,
    };

    let addToResourcePolicyResults = k9.events.grantAccessViaResourcePolicy(eventBusResourcePolicyProps);
    console.log('addToResourcePolicyResults: ' + addToResourcePolicyResults);

    for (let result of addToResourcePolicyResults) {
      expect(result.statementAdded).toBeTruthy();
    }

    expectCDK(stack).to(haveResource('AWS::Events::EventBus'));
    expectCDK(stack).to(haveResource('AWS::Events::EventBusPolicy'));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

  test('Policy generation — specific principals', () => {
    const eventBusResourcePolicyProps: K9EventBusResourcePolicyProps = {
      bus: new events.EventBus(new cdk.Stack(app, 'K9EventBusPolicyGen'), 'test-bus'),
      k9DesiredAccess: desiredAccess,
    };

    const policy = k9.events.makeResourcePolicy(eventBusResourcePolicyProps);
    let policyStr = stringifyPolicy(policy);
    console.log('EventBridge policy: ' + policyStr);

    let policyObj = JSON.parse(policyStr);
    let statements = policyObj.Statement;
    expect(statements).toBeDefined();

    // Should have 3 Allow statements (administer-resource, read-config, write-data)
    // + 1 DenyEveryoneElse
    expect(statements.length).toEqual(4);

    let sids = statements.map((s: any) => s.Sid);
    expect(sids).toContain('AllowRestrictedAdministerResource');
    expect(sids).toContain('AllowRestrictedReadConfig');
    expect(sids).toContain('AllowRestrictedWriteData');
    expect(sids).toContain(SID_DENY_EVERYONE_ELSE);

    // Verify Allow statements use aws:PrincipalArn condition
    for (let stmt of statements) {
      if (stmt.Sid.startsWith('AllowRestricted')) {
        expect(stmt.Effect).toEqual('Allow');
        expect(stmt.Condition.ArnEquals).toBeDefined();
        expect(stmt.Condition.ArnEquals['aws:PrincipalArn']).toBeDefined();
      }
    }

    // Verify DenyEveryoneElse
    let denyStmt = statements.find((s: any) => s.Sid === SID_DENY_EVERYONE_ELSE);
    expect(denyStmt.Effect).toEqual('Deny');
    expect(denyStmt.Action).toEqual('events:*');
    expect(denyStmt.Condition.Bool['aws:PrincipalIsAWSService']).toEqual(['false']);
    expect(denyStmt.Condition.ArnNotEquals['aws:PrincipalArn']).toBeDefined();
  });

  test('Org-scoped access — wildcard + org constraint', () => {
    const orgDesiredAccess = new Array<IAccessSpec>(
      {
        accessCapabilities: [
          AccessCapability.ADMINISTER_RESOURCE,
          AccessCapability.READ_CONFIG,
        ],
        allowPrincipalArns: administerResourceArns,
      },
      {
        accessCapabilities: AccessCapability.WRITE_DATA,
        allowPrincipalArns: ['*'],
        restrictToPrincipalOrgIDs: ['o-abc123'],
      },
    );

    const eventBusResourcePolicyProps: K9EventBusResourcePolicyProps = {
      bus: new events.EventBus(new cdk.Stack(app, 'K9EventBusOrgScoped'), 'test-bus-org'),
      k9DesiredAccess: orgDesiredAccess,
    };

    const policy = k9.events.makeResourcePolicy(eventBusResourcePolicyProps);
    let policyStr = stringifyPolicy(policy);
    console.log('EventBridge org-scoped policy: ' + policyStr);

    let policyObj = JSON.parse(policyStr);
    let statements = policyObj.Statement;

    // Should have 3 Allow statements + DenyUntrustedOrgs but NO DenyEveryoneElse (wildcard principal present)
    expect(statements.length).toEqual(4);

    let sids = statements.map((s: any) => s.Sid);
    expect(sids).toContain('AllowRestrictedAdministerResource');
    expect(sids).toContain('AllowRestrictedReadConfig');
    expect(sids).toContain('AllowRestrictedWriteData');
    expect(sids).not.toContain(SID_DENY_EVERYONE_ELSE);
    expect(sids).toContain(SID_DENY_UNTRUSTED_ORGS);

    // Verify write-data statement uses aws:PrincipalOrgID condition (not aws:PrincipalArn)
    let writeStmt = statements.find((s: any) => s.Sid === 'AllowRestrictedWriteData');
    expect(writeStmt.Condition.StringEquals).toBeDefined();
    expect(writeStmt.Condition.StringEquals['aws:PrincipalOrgID']).toEqual(['o-abc123']);
    expect(writeStmt.Condition.ArnEquals).toBeUndefined();

    // Verify administer-resource still uses aws:PrincipalArn (specific ARNs)
    let adminStmt = statements.find((s: any) => s.Sid === 'AllowRestrictedAdministerResource');
    expect(adminStmt.Condition.ArnEquals).toBeDefined();
    expect(adminStmt.Condition.ArnEquals['aws:PrincipalArn']).toBeDefined();

    // Verify DenyUntrustedOrgs statement
    let denyUntrustedOrgsStmt = statements.find((s: any) => s.Sid === SID_DENY_UNTRUSTED_ORGS);
    expect(denyUntrustedOrgsStmt.Effect).toEqual('Deny');
    expect(denyUntrustedOrgsStmt.Condition.StringNotEquals['aws:PrincipalOrgID']).toEqual(['o-abc123']);
  });

  test('Specific principals + org constraint', () => {
    const orgConstrainedAccess = new Array<IAccessSpec>(
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
        restrictToPrincipalOrgIDs: ['o-abc123'],
      },
    );

    const eventBusResourcePolicyProps: K9EventBusResourcePolicyProps = {
      bus: new events.EventBus(new cdk.Stack(app, 'K9EventBusSpecificPlusOrg'), 'test-bus-specific-org'),
      k9DesiredAccess: orgConstrainedAccess,
    };

    const policy = k9.events.makeResourcePolicy(eventBusResourcePolicyProps);
    let policyStr = stringifyPolicy(policy);
    console.log('EventBridge specific+org policy: ' + policyStr);

    let policyObj = JSON.parse(policyStr);
    let statements = policyObj.Statement;

    // Should have 3 Allow statements + DenyEveryoneElse + DenyUntrustedOrgs (no wildcard principals)
    expect(statements.length).toEqual(5);

    let sids = statements.map((s: any) => s.Sid);
    expect(sids).toContain(SID_DENY_EVERYONE_ELSE);
    expect(sids).toContain(SID_DENY_UNTRUSTED_ORGS);

    // Verify write-data has BOTH aws:PrincipalArn AND aws:PrincipalOrgID conditions
    let writeStmt = statements.find((s: any) => s.Sid === 'AllowRestrictedWriteData');
    expect(writeStmt.Condition.ArnEquals).toBeDefined();
    expect(writeStmt.Condition.ArnEquals['aws:PrincipalArn']).toBeDefined();
    expect(writeStmt.Condition.StringEquals).toBeDefined();
    expect(writeStmt.Condition.StringEquals['aws:PrincipalOrgID']).toEqual(['o-abc123']);

    // Verify DenyUntrustedOrgs statement
    let denyUntrustedOrgsStmt = statements.find((s: any) => s.Sid === SID_DENY_UNTRUSTED_ORGS);
    expect(denyUntrustedOrgsStmt.Effect).toEqual('Deny');
    expect(denyUntrustedOrgsStmt.Condition.StringNotEquals['aws:PrincipalOrgID']).toEqual(['o-abc123']);
  });

  test('Specific principals + multi-account multi-org constraint with wildcards', () => {
    const multiAccountWriteArns = [
      'arn:aws:iam::222222222222:role/app-a-publisher',
      'arn:aws:iam::222222222222:role/event-pub-*',
      'arn:aws:iam::333333333333:role/app-*-writer-*',
    ];

    const multiOrgAccess = new Array<IAccessSpec>(
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
        allowPrincipalArns: multiAccountWriteArns,
        test: 'ArnLike',
        restrictToPrincipalOrgIDs: ['o-abc123', 'o-def345'],
      },
    );

    const eventBusResourcePolicyProps: K9EventBusResourcePolicyProps = {
      bus: new events.EventBus(new cdk.Stack(app, 'K9EventBusMultiAccountMultiOrg'), 'test-bus-multi-acct-org'),
      k9DesiredAccess: multiOrgAccess,
    };

    const policy = k9.events.makeResourcePolicy(eventBusResourcePolicyProps);
    let policyStr = stringifyPolicy(policy);
    console.log('EventBridge multi-account+multi-org policy: ' + policyStr);

    let policyObj = JSON.parse(policyStr);
    let statements = policyObj.Statement;

    // Should have 3 Allow statements + DenyEveryoneElse + DenyUntrustedOrgs (specific principals, not wildcard)
    expect(statements.length).toEqual(5);

    let sids = statements.map((s: any) => s.Sid);
    expect(sids).toContain('AllowRestrictedAdministerResource');
    expect(sids).toContain('AllowRestrictedReadConfig');
    expect(sids).toContain('AllowRestrictedWriteData');
    expect(sids).toContain(SID_DENY_EVERYONE_ELSE);
    expect(sids).toContain(SID_DENY_UNTRUSTED_ORGS);

    // Verify write-data uses ArnLike (wildcards in ARNs) with BOTH PrincipalArn AND PrincipalOrgID
    let writeStmt = statements.find((s: any) => s.Sid === 'AllowRestrictedWriteData');
    expect(writeStmt.Condition.ArnLike).toBeDefined();
    expect(writeStmt.Condition.ArnLike['aws:PrincipalArn']).toEqual(multiAccountWriteArns);
    expect(writeStmt.Condition.ArnEquals).toBeUndefined();
    expect(writeStmt.Condition.StringEquals).toBeDefined();
    expect(writeStmt.Condition.StringEquals['aws:PrincipalOrgID']).toEqual(['o-abc123', 'o-def345']);

    // Verify administer-resource uses ArnLike but does NOT have org constraint
    let adminStmt = statements.find((s: any) => s.Sid === 'AllowRestrictedAdministerResource');
    expect(adminStmt.Condition.ArnLike).toBeDefined();
    expect(adminStmt.Condition.ArnLike['aws:PrincipalArn']).toBeDefined();
    expect(adminStmt.Condition.StringEquals).toBeUndefined();

    // Verify DenyEveryoneElse uses ArnNotLike (because ArnLike was used) and includes all principals
    let denyStmt = statements.find((s: any) => s.Sid === SID_DENY_EVERYONE_ELSE);
    expect(denyStmt.Condition.ArnNotLike).toBeDefined();
    expect(denyStmt.Condition.ArnNotEquals).toBeUndefined();
    let denyExceptionArns = denyStmt.Condition.ArnNotLike['aws:PrincipalArn'];
    for (let arn of multiAccountWriteArns) {
      expect(denyExceptionArns).toContain(arn);
    }
    for (let arn of administerResourceArns) {
      expect(denyExceptionArns).toContain(arn);
    }

    // Verify DenyUntrustedOrgs statement with multiple org IDs
    let denyUntrustedOrgsStmt = statements.find((s: any) => s.Sid === SID_DENY_UNTRUSTED_ORGS);
    expect(denyUntrustedOrgsStmt.Effect).toEqual('Deny');
    expect(denyUntrustedOrgsStmt.Condition.StringNotEquals['aws:PrincipalOrgID']).toEqual(['o-abc123', 'o-def345']);
  });

  test('Snapshot — typical usage', () => {
    const stack = new cdk.Stack(app, 'K9EventBusSnapshot', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-snapshot');

    k9.events.grantAccessViaResourcePolicy({
      bus: bus,
      k9DesiredAccess: desiredAccess,
    });

    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

  test('Snapshot — org-scoped access', () => {
    const stack = new cdk.Stack(app, 'K9EventBusOrgSnapshot', { env: { region: 'us-east-1' } });
    const bus = new events.EventBus(stack, 'test-bus-org-snapshot');

    k9.events.grantAccessViaResourcePolicy({
      bus: bus,
      k9DesiredAccess: new Array<IAccessSpec>(
        {
          accessCapabilities: [
            AccessCapability.ADMINISTER_RESOURCE,
            AccessCapability.READ_CONFIG,
          ],
          allowPrincipalArns: administerResourceArns,
        },
        {
          accessCapabilities: AccessCapability.WRITE_DATA,
          allowPrincipalArns: ['*'],
          restrictToPrincipalOrgIDs: ['o-abc123'],
        },
      ),
    });

    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });
});

describe('EventBusResourcePolicy validation', () => {
  test('throws error for empty allowPrincipalArns', () => {
    const stack = new cdk.Stack(app, 'K9EventBusValidateEmpty');
    const bus = new events.EventBus(stack, 'test-bus-empty');

    expect(() => k9.events.makeResourcePolicy({
      bus: bus,
      k9DesiredAccess: [
        {
          accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
          allowPrincipalArns: [],
        },
      ],
    })).toThrow('allowPrincipalArns must not be empty');
  });

  test('throws error for wildcard without org constraint (public access)', () => {
    const stack = new cdk.Stack(app, 'K9EventBusValidatePublic');
    const bus = new events.EventBus(stack, 'test-bus-public');

    expect(() => k9.events.makeResourcePolicy({
      bus: bus,
      k9DesiredAccess: [
        {
          accessCapabilities: [
            AccessCapability.ADMINISTER_RESOURCE,
            AccessCapability.READ_CONFIG,
          ],
          allowPrincipalArns: administerResourceArns,
        },
        {
          accessCapabilities: AccessCapability.WRITE_DATA,
          allowPrincipalArns: ['*'],
        },
      ],
    })).toThrow('k9-cdk will not generate a resource policy that allows fully public access');
  });

  test('throws error when no principal can manage resources', () => {
    const stack = new cdk.Stack(app, 'K9EventBusValidateManage');
    const bus = new events.EventBus(stack, 'test-bus-manage');

    expect(() => k9.events.makeResourcePolicy({
      bus: bus,
      k9DesiredAccess: [
        {
          accessCapabilities: AccessCapability.WRITE_DATA,
          allowPrincipalArns: writeDataArns,
        },
      ],
    })).toThrow('At least one principal must be able to administer and read-config for EventBridge resources');
  });
});
