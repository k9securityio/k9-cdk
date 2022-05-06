import {AnyPrincipal, PolicyStatement} from 'aws-cdk-lib/aws-iam';
import {AccessCapability, getAccessCapabilityFromValue, IAccessSpec, K9PolicyFactory} from '../lib/k9policy';
import {stringifyStatement} from './helpers';

const S3_SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
  AccessCapability.ADMINISTER_RESOURCE,
  AccessCapability.READ_CONFIG,
  AccessCapability.READ_DATA,
  AccessCapability.WRITE_DATA,
  AccessCapability.DELETE_DATA,
);

test('getAccessCapabilityFromValue resolves defined capabilities', () => {
  expect(getAccessCapabilityFromValue("administer-resource"))
      .toEqual(AccessCapability.ADMINISTER_RESOURCE);
  expect(getAccessCapabilityFromValue("read-data"))
      .toEqual(AccessCapability.READ_DATA);
  expect(getAccessCapabilityFromValue("read-config"))
      .toEqual(AccessCapability.READ_CONFIG);
});

test('getAccessCapabilityFromValue throws error for undefined capabilities', () => {
  expect(() => {
    getAccessCapabilityFromValue("unknown-capability")
  }).toThrow(`Could not get AccessCapability from value: unknown-capability`);
});

test('K9PolicyFactory#wasLikeUsed', () => {
  let k9PolicyFactory = new K9PolicyFactory();
  expect(k9PolicyFactory.wasLikeUsed([])).toBeFalsy();
  expect(k9PolicyFactory.wasLikeUsed([
    {
      accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
      allowPrincipalArns: [],
      test: 'ArnEquals',
    },
  ])).toBeFalsy();

  expect(k9PolicyFactory.wasLikeUsed([
    {
      accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
      allowPrincipalArns: [],
      test: 'ArnLike',
    },
  ])).toBeTruthy();
});

test('K9PolicyFactory#getAllowedPrincipalArns', () => {
  let k9PolicyFactory = new K9PolicyFactory();
  let accessSpecs:Array<IAccessSpec> = [
    {
      accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
      allowPrincipalArns: ['arn1', 'arn2'],
      test: 'ArnEquals',
    },
    {
      accessCapabilities: AccessCapability.READ_DATA,
      allowPrincipalArns: ['arn2', 'arn3'],
      test: 'ArnLike',
    },

  ];
  expect(k9PolicyFactory.getAllowedPrincipalArns([])).toEqual(new Array<string>());
  expect(k9PolicyFactory.getAllowedPrincipalArns(accessSpecs))
    .toEqual(['arn1', 'arn2', 'arn3']);
});

// noinspection JSUnusedLocalSymbols
// @ts-ignore
function logStatement(stmt: PolicyStatement) {
  let statementJsonStr = stringifyStatement(stmt);
  console.log(`actual policy statement: ${stmt} json: ${statementJsonStr}`);
}

describe('K9PolicyFactory#makeAllowStatements', () => {
  const k9PolicyFactory = new K9PolicyFactory();
  const adminPrincipalArns = ['arn1', 'arn2'];
  const resourceArns = ['resource_arn_1', 'resource_arn_2'];


  test('single access capability specs', () => {
    const readerPrincipalArns = ['arn2', 'arn3'];

    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: adminPrincipalArns,
        test: 'ArnEquals',
      },
      {
        accessCapabilities: AccessCapability.READ_DATA,
        allowPrincipalArns: readerPrincipalArns,
        test: 'ArnLike',
      },

    ];
    let supportedCapabilities = [AccessCapability.ADMINISTER_RESOURCE, AccessCapability.READ_DATA];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      supportedCapabilities,
      accessSpecs,
      resourceArns);
    expect(actualPolicyStatements.length).toEqual(2);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);
      if ('Allow Restricted read-data' == stmt.sid) {
        expect(statementObj.Resource).toEqual(resourceArns);
        expect(statementObj.Condition).toEqual({
          ArnLike: {
            'aws:PrincipalArn': readerPrincipalArns,
          },
        },
        );
      } else if ('Allow Restricted administer-resource' == stmt.sid) {
        expect(statementObj.Resource).toEqual(resourceArns);
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns,
          },
        },
        );
      } else {
        fail(`Unexpected statement ${stmt.sid}`);
      }

    }
  });

  test('mixed single and multi access capability specs', () => {
    const readWritePrincipalArns = ['arn2', 'arn4'];

    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: adminPrincipalArns,
        test: 'ArnEquals',
      },
      {
        accessCapabilities: [AccessCapability.READ_DATA, AccessCapability.WRITE_DATA],
        allowPrincipalArns: readWritePrincipalArns,
        test: 'ArnLike',
      },

    ];

    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      S3_SUPPORTED_CAPABILITIES,
      accessSpecs,
      resourceArns);

    expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);

      expect(statementObj.Resource).toEqual(resourceArns);
      if (('Allow Restricted read-data' == stmt.sid) ||
                ('Allow Restricted write-data' == stmt.sid)) {
        expect(statementObj.Condition).toEqual({
          ArnLike: {
            'aws:PrincipalArn': readWritePrincipalArns,
          },
        },
        );
      } else if ('Allow Restricted administer-resource' == stmt.sid) {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns,
          },
        },
        );
      } else {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': [],
          },
        },
        );
      }

    }
  });

  test('multi access capability specs', () => {
    let readWritePrincipalArns = ['arn2', 'arn3'];
    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: [AccessCapability.ADMINISTER_RESOURCE, AccessCapability.READ_CONFIG],
        allowPrincipalArns: adminPrincipalArns,
        test: 'ArnEquals',
      },
      {
        accessCapabilities: [AccessCapability.READ_DATA, AccessCapability.WRITE_DATA],
        allowPrincipalArns: readWritePrincipalArns,
        test: 'ArnLike',
      },

    ];

    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      S3_SUPPORTED_CAPABILITIES,
      accessSpecs,
      resourceArns);

    expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);

      expect(statementObj.Resource).toEqual(resourceArns);
      if (('Allow Restricted read-data' == stmt.sid) ||
                ('Allow Restricted write-data' == stmt.sid)) {
        expect(statementObj.Condition).toEqual({
          ArnLike: {
            'aws:PrincipalArn': readWritePrincipalArns,
          },
        },
        );
      } else if (('Allow Restricted administer-resource' == stmt.sid) ||
                ('Allow Restricted read-config' == stmt.sid)) {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns,
          },
        },
        );
      } else {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': [],
          },
        },
        );
      }

    }
  });

  test('multiple access specs for a single capability - read-config', () => {
    let addlConfigReaders = ['_internal-tool', 'auditor', 'observability'];
    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: [AccessCapability.ADMINISTER_RESOURCE, AccessCapability.READ_CONFIG],
        allowPrincipalArns: adminPrincipalArns,
        test: 'ArnEquals',
      },

      {
        accessCapabilities: [AccessCapability.READ_CONFIG],
        allowPrincipalArns: addlConfigReaders,
        test: 'ArnEquals',
      },
    ];

    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      S3_SUPPORTED_CAPABILITIES,
      accessSpecs,
      resourceArns);

    expect(actualPolicyStatements.length).toEqual(S3_SUPPORTED_CAPABILITIES.length);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);

      expect(statementObj.Resource).toEqual(resourceArns);
      if ('Allow Restricted administer-resource' == stmt.sid) {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns,
          },
        },
        );
      } else if ('Allow Restricted read-config' == stmt.sid) {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns.concat(addlConfigReaders),
          },
        },
        );
      } else {
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': [],
          },
        },
        );
      }

    }
  });

  test('throws an Error when ArnConditionTest mismatches between AccessSpecs', () => {
    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: adminPrincipalArns,
        test: 'ArnEquals',
      },
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: ['more-admin-roles*'],
        test: 'ArnLike',
      },
    ];
    let supportedCapabilities = [AccessCapability.ADMINISTER_RESOURCE];

    expect(() => k9PolicyFactory.makeAllowStatements('S3',
      supportedCapabilities,
      accessSpecs,
      resourceArns)).toThrow(/Cannot merge AccessSpecs; test attributes do not match/);

  });

  test('uses unique set of principals', () => {
    const duplicatedPrincipals = adminPrincipalArns.concat(adminPrincipalArns);

    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: duplicatedPrincipals,
      },
    ];
    let supportedCapabilities = [AccessCapability.ADMINISTER_RESOURCE];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      supportedCapabilities,
      accessSpecs,
      resourceArns);
    expect(actualPolicyStatements.length).toEqual(1);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);
      if ('Allow Restricted administer-resource' == stmt.sid) {
        expect(statementObj.Resource).toEqual(resourceArns);
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': Array.from(new Set<string>(duplicatedPrincipals.values())).sort(),
          },
        },
        );
      } else {
        fail(`Unexpected statement ${stmt.sid}`);
      }
    }
  });

  test('defaults ArnConditionTest to ArnEquals', () => {
    let accessSpecs: Array<IAccessSpec> = [
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: adminPrincipalArns,
      },
    ];
    let supportedCapabilities = [AccessCapability.ADMINISTER_RESOURCE];
    let actualPolicyStatements = k9PolicyFactory.makeAllowStatements('S3',
      supportedCapabilities,
      accessSpecs,
      resourceArns);
    expect(actualPolicyStatements.length).toEqual(1);

    for (let stmt of actualPolicyStatements) {
      let statementJsonStr = stringifyStatement(stmt);
      let statementObj = JSON.parse(statementJsonStr);
      if ('Allow Restricted administer-resource' == stmt.sid) {
        expect(statementObj.Resource).toEqual(resourceArns);
        expect(statementObj.Condition).toEqual({
          ArnEquals: {
            'aws:PrincipalArn': adminPrincipalArns,
          },
        },
        );
      } else {
        fail(`Unexpected statement ${stmt.sid}`);
      }
    }
  });
});

test('K9PolicyFactory#deduplicatePrincipals', () => {
  const roleDefinedDirectlyByArn = 'arn:aws:iam::123456789012:role/some-role';

  const roleDefinedInStack = {
    'Fn::GetAtt': [
      'someAutoGeneratedRoleE9062A9C',
      'Arn',
    ],
  };
  const roleImportedFromAnotherStack = {
    'Fn::ImportValue': 'some-shared-stack:ExportsOutputFnGetAttSomeRole8DFA0181Arn43EC6E0B',
  };

  const expectPrincipals: Array<string | object> = [
    roleDefinedDirectlyByArn,
    roleDefinedInStack,
    roleImportedFromAnotherStack,
  ];


  for (let i = 0; i < 100; i++) {
    const principalsWithDuplicates: Array<string | object> = expectPrincipals.concat(
      ...(expectPrincipals.concat().reverse()),
    );

    const uniquePrincipals: Array<string | object> = K9PolicyFactory.deduplicatePrincipals(principalsWithDuplicates);
    expect(uniquePrincipals).toEqual(expectPrincipals);

  }

});

test('K9PolicyFactory#makeDenyEveryoneElsePrincipals', () => {
  let k9PolicyFactory = new K9PolicyFactory();
  let denyEveryoneElsePrincipals = k9PolicyFactory.makeDenyEveryoneElsePrincipals();
  expect(denyEveryoneElsePrincipals.length).toBeGreaterThan(1);
  const anyPrincipal = new AnyPrincipal();
  for (let principal of denyEveryoneElsePrincipals) {
    expect(principal).toEqual(anyPrincipal);
    expect(principal).toBeInstanceOf(AnyPrincipal);
  }
});
