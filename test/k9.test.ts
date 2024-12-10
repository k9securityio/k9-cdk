import { expect as expectCDK, haveResource, SynthUtils } from '@aws-cdk/assert';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { AddToResourcePolicyResult } from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { BucketEncryption } from 'aws-cdk-lib/aws-s3';
import * as cdk from 'aws-cdk-lib/core';
import { RemovalPolicy } from 'aws-cdk-lib/core';
import { fail, stringifyPolicy } from './helpers';
import * as k9 from '../lib';
import { AccessCapability, IAccessSpec, IAWSServiceAccessGenerator } from '../lib/k9policy';
import { K9KeyPolicyProps, SID_ALLOW_ROOT_AND_IDENTITY_POLICIES, SID_DENY_EVERYONE_ELSE } from '../lib/kms';
import {
  K9BucketPolicyProps,
  SID_ALLOW_PUBLIC_READ_ACCESS,
  SID_DENY_UNENCRYPTED_STORAGE,
  SID_DENY_UNEXPECTED_ENCRYPTION_METHOD,
  CloudFrontOACReadAccessGenerator,
} from '../lib/s3';
import { K9DynamoDBResourcePolicyProps } from '../src/dynamodb';
// @ts-ignore

// Test the primary public interface to k9 cdk

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

test('K9BucketPolicy - typical usage', () => {
  const stack = new cdk.Stack(app, 'K9PolicyTestTypicalUsage');
  const bucket = new s3.Bucket(stack, 'TestBucket', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
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
    ),
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'S3Bucket', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  for (let stmt of actualPolicyStatements) {
    if (SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
      expect(stmt.Condition.StringNotEquals['s3:x-amz-server-side-encryption']).toEqual('aws:kms');
    }
  }

  expectCDK(stack).to(haveResource('AWS::S3::Bucket'));
  expectCDK(stack).to(haveResource('AWS::S3::BucketPolicy'));
  expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});


test('K9BucketPolicy - do not enforce KMS encryption at rest when configured off', () => {
  const stack = new cdk.Stack(app, 'K9PolicyTestNoKMSEnforcement');
  const bucket = new s3.Bucket(stack, 'TestBucketNoKMSEnforcement', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    enforceEncryptionAtRest: false,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
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
    ),
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'S3Bucket', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults, k9BucketPolicyProps);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  for (let stmt of actualPolicyStatements) {
    if (SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
      fail(`should not have a '${SID_DENY_UNEXPECTED_ENCRYPTION_METHOD}' statement`);
    }
    if (SID_DENY_UNENCRYPTED_STORAGE == stmt.Sid) {
      fail(`should not have a '${SID_DENY_UNENCRYPTED_STORAGE}' statement`);
    }
  }

  expectCDK(stack).to(haveResource('AWS::S3::Bucket'));
  expectCDK(stack).to(haveResource('AWS::S3::BucketPolicy'));
  expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});

test('K9BucketPolicy - specify encryption method - KMS', () => {
  const stack = new cdk.Stack(app, 'K9BucketPolicyWithEncryptionMethodKMS');
  const bucket = new s3.Bucket(stack, 'TestBucketWithEncryptionMethodKMS', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: administerResourceArns,
      },
    ),
    encryption: BucketEncryption.KMS,
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'BucketPolicyWithEncryptionMethodKMS', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  for (let stmt of actualPolicyStatements) {
    if (SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
      expect(stmt.Condition.StringNotEquals['s3:x-amz-server-side-encryption']).toEqual('aws:kms');
    }
  }

});

test('K9BucketPolicy - specify encryption method - S3_MANAGED', () => {
  const stack = new cdk.Stack(app, 'K9BucketPolicyAlternateEncryptionMethod');
  const bucket = new s3.Bucket(stack, 'TestBucketWithAlternateEncryptionMethod', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: administerResourceArns,
      },
    ),
    encryption: BucketEncryption.S3_MANAGED,
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'BucketPolicyWithAlternateEncryptionMethod', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  for (let stmt of actualPolicyStatements) {
    if (SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
      expect(stmt.Condition.StringNotEquals['s3:x-amz-server-side-encryption']).toEqual('AES256');
    }
  }

});

//public bucket use case: generate a policy that says sse-s3 is required and read-data by public is ok
//but write-data is protected for example.
test('K9BucketPolicy - for a public website (direct to S3) - sse-s3 + public-read + restricted-write ', () => {
  const stack = new cdk.Stack(app, 'K9BucketPolicyPublicWebsite');
  const bucket = new s3.Bucket(stack, 'TestBucketForPublicWebsite', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: administerResourceArns,
      },
    ),
    encryption: BucketEncryption.S3_MANAGED,
    publicReadAccess: true,
  };

  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'BucketPolicyForPublicWebsite', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults, k9BucketPolicyProps);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  assertContainsStatementWithId(SID_ALLOW_PUBLIC_READ_ACCESS, actualPolicyStatements);

  for (let stmt of actualPolicyStatements) {
    if (SID_ALLOW_PUBLIC_READ_ACCESS == stmt.Sid) {
      expect(stmt.Principal).toEqual({ AWS: '*' });
      expect(stmt.Action).toEqual('s3:GetObject');
    } else if (SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
      expect(stmt.Condition.StringNotEquals['s3:x-amz-server-side-encryption']).toEqual('AES256');
    }
  }

});

test('K9BucketPolicy - allow CloudFront OAC', () => {
  const stack = new cdk.Stack(app, 'K9BucketPolicyCloudFrontOAC');
  const bucket = new s3.Bucket(stack, 'TestBucketForCloudFrontOAC', {});

  let expectDistributionArn = 'arn:aws:cloudfront::123456789012:distribution/DIST_ID_1234';
  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: administerResourceArns,
      },
    ),
    encryption: BucketEncryption.S3_MANAGED,

    awsServiceAccessGenerators: new Array<IAWSServiceAccessGenerator>(
      new CloudFrontOACReadAccessGenerator(bucket, expectDistributionArn),
    ),
  };

  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'K9BucketPolicyCloudFrontOAC', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  let policyStr = stringifyPolicy(bucket.policy?.document);
  console.log('bucket.policy?.document: ' + policyStr);
  expect(bucket.policy?.document).toBeDefined();

  // assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults, k9BucketPolicyProps);
  console.log('addToResourcePolicyResults: '+ addToResourcePolicyResults);
  let policyObj = JSON.parse(policyStr);
  let actualPolicyStatements = policyObj.Statement;
  expect(actualPolicyStatements).toBeDefined();

  let expectAllowSid = CloudFrontOACReadAccessGenerator.SID_ALLOW_CLOUDFRONT_OAC_READ_ACCESS;
  assertContainsStatementWithId(expectAllowSid, actualPolicyStatements);

  for (let stmt of actualPolicyStatements) {
    if (SID_DENY_EVERYONE_ELSE == stmt.Sid) {
      expect(stmt.Condition.ArnNotEquals['aws:PrincipalArn']).toBeTruthy();
      expect(stmt.Condition.StringNotEqualsIfExists['aws:PrincipalServiceName']).toEqual('cloudfront.amazonaws.com');
    } else if (expectAllowSid == stmt.Sid) {
      expect(stmt.Condition.StringEquals['aws:SourceArn']).toEqual(expectDistributionArn);
    }
  }

});


test('K9BucketPolicy - IAccessSpec with set of capabilities', () => {
  const localstack = new cdk.Stack(app, 'K9BucketPolicyMultiAccessCapa');
  const bucket = new s3.Bucket(localstack, 'TestBucketWithMultiAccessSpec', {});

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: [
          AccessCapability.ADMINISTER_RESOURCE,
          AccessCapability.READ_CONFIG,
        ],
        allowPrincipalArns: administerResourceArns,
      },
      {
        accessCapabilities: [
          AccessCapability.READ_DATA,
          AccessCapability.WRITE_DATA,
          AccessCapability.DELETE_DATA,
        ],
        allowPrincipalArns: writeDataArns,
      },
    ),
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(localstack, 'S3BucketMultiAccessSpec', k9BucketPolicyProps);
  expect(bucket.policy).toBeDefined();

  console.log('bucket.policy?.document: ' + stringifyPolicy(bucket.policy?.document));
  expect(bucket.policy?.document).toBeDefined();

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);

  expectCDK(localstack).to(haveResource('AWS::S3::Bucket'));
  expectCDK(localstack).to(haveResource('AWS::S3::BucketPolicy'));
  expect(SynthUtils.toCloudFormation(localstack)).toMatchSnapshot();
});

test('k9.s3.grantAccessViaResourcePolicy merges permissions for autoDeleteObjects', () => {
  const stack = new cdk.Stack(app, 'ManagePermissionsForAutoDeleteObjects');
  const bucket = new s3.Bucket(stack, 'AutoDeleteBucket', {
    autoDeleteObjects: true,
    removalPolicy: RemovalPolicy.DESTROY,
  });

  let originalBucketPolicy = bucket.policy;
  expect(originalBucketPolicy).toBeTruthy();
  console.log('original bucketPolicy.document: ' + stringifyPolicy(bucket?.policy?.document));

  const k9BucketPolicyProps: K9BucketPolicyProps = {
    bucket: bucket,
    k9DesiredAccess: new Array<IAccessSpec>(
      {
        accessCapabilities: AccessCapability.ADMINISTER_RESOURCE,
        allowPrincipalArns: administerResourceArns,
      },
      {
        accessCapabilities: AccessCapability.DELETE_DATA,
        allowPrincipalArns: deleteDataArns,
      },
    ),
  };
  let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, 'AutoDeleteBucket', k9BucketPolicyProps);

  expect(bucket.policy).toStrictEqual(originalBucketPolicy);

  assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);

  console.log('k9 bucket policy: ' + stringifyPolicy(bucket.policy?.document));
  expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});

describe('K9KeyPolicy', () => {
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
  test('Without Allow root user and Identity policies', () => {
    const stack = new cdk.Stack(app, 'WithoutRootAndIdentityPolicies');
    const k9KeyPolicyProps: K9KeyPolicyProps = {
      k9DesiredAccess: desiredAccess,
    };

    expect(k9KeyPolicyProps.trustAccountIdentities).toBeFalsy();
    const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

    let policyJsonStr = stringifyPolicy(keyPolicy);
    console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
    let policyObj = JSON.parse(policyJsonStr);

    let actualPolicyStatements = policyObj.Statement;
    expect(actualPolicyStatements).toBeDefined();

    let denyEveryoneElseStmt: any;
    let allowRootStmt: any;
    for (let stmt of actualPolicyStatements) {
      if (SID_DENY_EVERYONE_ELSE == stmt.Sid) {
        denyEveryoneElseStmt = stmt;
      } else if (SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid) {
        allowRootStmt = stmt;
      }
    }

    expect(denyEveryoneElseStmt).toBeFalsy();
    expect(allowRootStmt).toBeFalsy();

    new kms.Key(stack, 'TestKeyNoRoot', { policy: keyPolicy });

    expectCDK(stack).to(haveResource('AWS::KMS::Key'));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

  test('Allow root user and Identity policies', () => {
    const stack = new cdk.Stack(app, 'WithRootAndIdentityPolicies');
    const k9KeyPolicyProps: K9KeyPolicyProps = {
      k9DesiredAccess: desiredAccess,
      trustAccountIdentities: true,
    };

    expect(k9KeyPolicyProps.trustAccountIdentities).toBeTruthy();
    const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

    let policyJsonStr = stringifyPolicy(keyPolicy);
    console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
    let policyObj = JSON.parse(policyJsonStr);

    let actualPolicyStatements = policyObj.Statement;
    expect(actualPolicyStatements).toBeDefined();

    let denyEveryoneElseStmt: any;
    let allowRootStmt: any;
    for (let stmt of actualPolicyStatements) {
      if (SID_DENY_EVERYONE_ELSE == stmt.Sid) {
        denyEveryoneElseStmt = stmt;
      } else if (SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid) {
        allowRootStmt = stmt;
      }
    }

    expect(denyEveryoneElseStmt).toBeTruthy();
    expect(allowRootStmt).toBeTruthy();


    new kms.Key(stack, 'TestKeyAllowRoot', { policy: keyPolicy });

    expectCDK(stack).to(haveResource('AWS::KMS::Key'));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });

  test('Unmanageable key policy is rejected', () => {

    const unmanageableCapabilityCombos = [
      [],
      [AccessCapability.ADMINISTER_RESOURCE],
      [AccessCapability.READ_CONFIG],
      [AccessCapability.ADMINISTER_RESOURCE, AccessCapability.WRITE_DATA],
    ];

    for (let trustAccountIdentities of [true, false]) {
      for (let unmanageableAccessCapabilities of unmanageableCapabilityCombos) {
        let localDesiredAccess = new Array<IAccessSpec>(
          {
            accessCapabilities: unmanageableAccessCapabilities,
            allowPrincipalArns: administerResourceArns,
          },
        );

        let k9KeyPolicyProps: K9KeyPolicyProps = {
          k9DesiredAccess: localDesiredAccess,
          trustAccountIdentities: trustAccountIdentities,
        };

        expect(() => k9.kms.makeKeyPolicy(k9KeyPolicyProps))
          .toThrow(/At least one principal must be able to administer and read-config for keys/);

      }

    }
  });

  test('Allow CloudFront Service and IAM role with OAC generator', () => {
    const stack = new cdk.Stack(app, 'WithCloudFrontOAC');
    let expectDistributionArn = 'arn:aws:cloudfront::123456789012:distribution/DIST_ID_1234';
    const k9KeyPolicyProps: K9KeyPolicyProps = {
      k9DesiredAccess: desiredAccess,
      awsServiceAccessGenerators: new Array<IAWSServiceAccessGenerator>(
        new k9.kms.CloudFrontOACReadAccessGenerator(expectDistributionArn),
      ),
    };

    const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);

    let policyJsonStr = stringifyPolicy(keyPolicy);
    console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
    let policyObj = JSON.parse(policyJsonStr);

    let actualPolicyStatements = policyObj.Statement;
    expect(actualPolicyStatements).toBeDefined();

    let allowCloudFrontSvcReadDataSid = k9.kms.CloudFrontOACReadAccessGenerator.SID_ALLOW_CLOUDFRONT_SVC_READ_DATA;
    let allowCloudFrontIAMRoleReadDataSid = k9.kms.CloudFrontOACReadAccessGenerator.SID_ALLOW_CLOUDFRONT_IAM_ROLE_READ_DATA;
    for (let stmt of actualPolicyStatements) {
      if (allowCloudFrontSvcReadDataSid == stmt.Sid) {
        expect(stmt.Principal.Service).toContain('${Token[cloudfront.amazonaws.com');
        expect(stmt.Condition.StringEquals['aws:SourceArn']).toEqual(expectDistributionArn);
      } else if (allowCloudFrontIAMRoleReadDataSid == stmt.Sid) {
        expect(stmt.Principal.AWS).toEqual('*');
        expect(stmt.Condition.ArnEquals['aws:PrincipalArn']).toEqual('arn:aws:iam::856369053181:role/OriginAccessControlRole');
      }
    }

    new kms.Key(stack, 'TestKeyWithCloudFrontOAC', { policy: keyPolicy });

    expectCDK(stack).to(haveResource('AWS::KMS::Key'));
    expect(SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
  });


});

describe('DynamoDBResourcePolicy', () => {
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
    const stack = new cdk.Stack(app, 'K9DDBResourcePolicyTestTypicalUsage', { env: { region: 'us-east-1' } });

    const ddbResourcePolicyProps: K9DynamoDBResourcePolicyProps = {
      k9DesiredAccess: desiredAccess,
    };

    const table = new dynamodb.TableV2(stack, 'test-table-typical-usage', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      // resourcePolicy: resourcePolicy,
    });

    let addToResourcePolicyResults = k9.dynamodb.grantAccessViaResourcePolicy(table, ddbResourcePolicyProps);

    console.log('table: ' + table);
    console.log('table.resourcePolicy: ' + stringifyPolicy(table.resourcePolicy));
    console.log('addToResourcePolicyResults: ' + addToResourcePolicyResults);

    expect(table.resourcePolicy).toBeDefined();

    let policyStr = stringifyPolicy(table.resourcePolicy);

    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj.Statement;
    expect(actualPolicyStatements).toBeDefined();

    const expectStmtIds = [
      SID_DENY_EVERYONE_ELSE,
      'AllowRestrictedAdministerResource',
      'AllowRestrictedReadConfig',
      'AllowRestrictedReadData',
      'AllowRestrictedWriteData',
      'AllowRestrictedDeleteData',
    ];
    expect(actualPolicyStatements).toHaveLength(expectStmtIds.length);
    expect(addToResourcePolicyResults).toHaveLength(expectStmtIds.length);

    const policyStatementMap: { [key: string]: any } = {};
    for (let stmt of actualPolicyStatements) {
      if (stmt.Sid) {
        policyStatementMap[stmt.Sid] = stmt;
      }
    }

    for (let expectStmtId of expectStmtIds) {
      expect(policyStatementMap[expectStmtId]).toBeTruthy();
    }
  });

});


function assertContainsStatementWithId(expectStmtId:string, statements:any) {
  let foundStmt = false;
  console.log(`looking for statement id: ${expectStmtId}`);
  for (let stmt of statements) {
    if (expectStmtId == stmt.Sid) {
      foundStmt = true;
      break;
    }
  }
  expect(foundStmt).toBeTruthy();
}

function assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults: AddToResourcePolicyResult[],
  k9BucketPolicyProps?: K9BucketPolicyProps) {
  let numExpectedStatements = 9;
  if (k9BucketPolicyProps && k9BucketPolicyProps.publicReadAccess) {
    numExpectedStatements += 1;
  }
  if (k9BucketPolicyProps && !(k9BucketPolicyProps.enforceEncryptionAtRest ?? true)) {
    numExpectedStatements -= 2;
  }
  expect(addToResourcePolicyResults.length).toEqual(numExpectedStatements);
  for (let result of addToResourcePolicyResults) {
    expect(result.statementAdded).toBeTruthy();
  }
}
