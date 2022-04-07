"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("@aws-cdk/assert");
const cdk = require("@aws-cdk/core");
const core_1 = require("@aws-cdk/core");
const kms = require("@aws-cdk/aws-kms");
const s3 = require("@aws-cdk/aws-s3");
const aws_s3_1 = require("@aws-cdk/aws-s3");
const k9policy_1 = require("../lib/k9policy");
const s3_1 = require("../lib/s3");
const kms_1 = require("../lib/kms");
const k9 = require("../lib");
const helpers_1 = require("./helpers");
// Test the primary public interface to k9 cdk
const administerResourceArns = [
    "arn:aws:iam::139710491120:user/ci",
];
const writeDataArns = [
    "arn:aws:iam::123456789012:role/app-backend",
];
const readDataArns = writeDataArns.concat(["arn:aws:iam::123456789012:role/customer-service"]);
const deleteDataArns = [
    "arn:aws:iam::139710491120:user/super-admin",
];
const app = new cdk.App();
test('K9BucketPolicy - typical usage', () => {
    var _a, _b;
    const stack = new cdk.Stack(app, 'K9PolicyTestTypicalUsage');
    const bucket = new s3.Bucket(stack, 'TestBucket', {});
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        }, {
            accessCapabilities: k9policy_1.AccessCapability.WriteData,
            allowPrincipalArns: writeDataArns,
        }, {
            accessCapabilities: k9policy_1.AccessCapability.ReadData,
            allowPrincipalArns: readDataArns,
        }, {
            accessCapabilities: k9policy_1.AccessCapability.DeleteData,
            allowPrincipalArns: deleteDataArns,
        })
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "S3Bucket", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();
    let policyStr = helpers_1.stringifyPolicy((_a = bucket.policy) === null || _a === void 0 ? void 0 : _a.document);
    console.log("bucket.policy?.document: " + policyStr);
    expect((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document).toBeDefined();
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj['Statement'];
    expect(actualPolicyStatements).toBeDefined();
    for (let stmt of actualPolicyStatements) {
        if (s3_1.SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
            expect(stmt.Condition['StringNotEquals']['s3:x-amz-server-side-encryption']).toEqual('aws:kms');
        }
    }
    assert_1.expect(stack).to(assert_1.haveResource("AWS::S3::Bucket"));
    assert_1.expect(stack).to(assert_1.haveResource("AWS::S3::BucketPolicy"));
    expect(assert_1.SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});
test('K9BucketPolicy - specify encryption method - KMS', () => {
    var _a, _b;
    const stack = new cdk.Stack(app, 'K9BucketPolicyWithEncryptionMethodKMS');
    const bucket = new s3.Bucket(stack, 'TestBucketWithEncryptionMethodKMS', {});
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        }),
        encryption: aws_s3_1.BucketEncryption.KMS,
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "BucketPolicyWithEncryptionMethodKMS", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();
    let policyStr = helpers_1.stringifyPolicy((_a = bucket.policy) === null || _a === void 0 ? void 0 : _a.document);
    console.log("bucket.policy?.document: " + policyStr);
    expect((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document).toBeDefined();
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj['Statement'];
    expect(actualPolicyStatements).toBeDefined();
    for (let stmt of actualPolicyStatements) {
        if (s3_1.SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
            expect(stmt.Condition['StringNotEquals']['s3:x-amz-server-side-encryption']).toEqual('aws:kms');
        }
    }
});
test('K9BucketPolicy - specify encryption method - S3_MANAGED', () => {
    var _a, _b;
    const stack = new cdk.Stack(app, 'K9BucketPolicyAlternateEncryptionMethod');
    const bucket = new s3.Bucket(stack, 'TestBucketWithAlternateEncryptionMethod', {});
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        }),
        encryption: aws_s3_1.BucketEncryption.S3_MANAGED,
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "BucketPolicyWithAlternateEncryptionMethod", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();
    let policyStr = helpers_1.stringifyPolicy((_a = bucket.policy) === null || _a === void 0 ? void 0 : _a.document);
    console.log("bucket.policy?.document: " + policyStr);
    expect((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document).toBeDefined();
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj['Statement'];
    expect(actualPolicyStatements).toBeDefined();
    for (let stmt of actualPolicyStatements) {
        if (s3_1.SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
            expect(stmt.Condition['StringNotEquals']['s3:x-amz-server-side-encryption']).toEqual('AES256');
        }
    }
});
//public bucket use case: generate a policy that says sse-s3 is required and read-data by public is ok
//but write-data is protected for example.
test('K9BucketPolicy - for a public website (direct to S3) - sse-s3 + public-read + restricted-write ', () => {
    var _a, _b;
    const stack = new cdk.Stack(app, 'K9BucketPolicyPublicWebsite');
    const bucket = new s3.Bucket(stack, 'TestBucketForPublicWebsite', {});
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        }),
        encryption: aws_s3_1.BucketEncryption.S3_MANAGED,
        publicReadAccess: true
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "BucketPolicyForPublicWebsite", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();
    let policyStr = helpers_1.stringifyPolicy((_a = bucket.policy) === null || _a === void 0 ? void 0 : _a.document);
    console.log("bucket.policy?.document: " + policyStr);
    expect((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document).toBeDefined();
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults, k9BucketPolicyProps);
    let policyObj = JSON.parse(policyStr);
    let actualPolicyStatements = policyObj['Statement'];
    expect(actualPolicyStatements).toBeDefined();
    assertContainsStatementWithId(s3_1.SID_ALLOW_PUBLIC_READ_ACCESS, actualPolicyStatements);
    for (let stmt of actualPolicyStatements) {
        if (s3_1.SID_ALLOW_PUBLIC_READ_ACCESS == stmt.Sid) {
            expect(stmt.Principal).toEqual({ "AWS": "*" });
            expect(stmt.Action).toEqual('s3:GetObject');
        }
        else if (s3_1.SID_DENY_UNEXPECTED_ENCRYPTION_METHOD == stmt.Sid) {
            expect(stmt.Condition['StringNotEquals']['s3:x-amz-server-side-encryption']).toEqual('AES256');
        }
    }
});
test('K9BucketPolicy - AccessSpec with set of capabilities', () => {
    var _a, _b;
    const localstack = new cdk.Stack(app, 'K9BucketPolicyMultiAccessCapa');
    const bucket = new s3.Bucket(localstack, 'TestBucketWithMultiAccessSpec', {});
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: [
                k9policy_1.AccessCapability.AdministerResource,
                k9policy_1.AccessCapability.ReadConfig
            ],
            allowPrincipalArns: administerResourceArns,
        }, {
            accessCapabilities: [
                k9policy_1.AccessCapability.ReadData,
                k9policy_1.AccessCapability.WriteData,
                k9policy_1.AccessCapability.DeleteData,
            ],
            allowPrincipalArns: writeDataArns,
        })
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(localstack, "S3BucketMultiAccessSpec", k9BucketPolicyProps);
    expect(bucket.policy).toBeDefined();
    console.log("bucket.policy?.document: " + helpers_1.stringifyPolicy((_a = bucket.policy) === null || _a === void 0 ? void 0 : _a.document));
    expect((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document).toBeDefined();
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    assert_1.expect(localstack).to(assert_1.haveResource("AWS::S3::Bucket"));
    assert_1.expect(localstack).to(assert_1.haveResource("AWS::S3::BucketPolicy"));
    expect(assert_1.SynthUtils.toCloudFormation(localstack)).toMatchSnapshot();
});
test('k9.s3.grantAccessViaResourcePolicy merges permissions for autoDeleteObjects', () => {
    var _a, _b;
    const stack = new cdk.Stack(app, 'ManagePermissionsForAutoDeleteObjects');
    const bucket = new s3.Bucket(stack, 'AutoDeleteBucket', {
        autoDeleteObjects: true,
        removalPolicy: core_1.RemovalPolicy.DESTROY
    });
    let originalBucketPolicy = bucket.policy;
    expect(originalBucketPolicy).toBeTruthy();
    console.log("original bucketPolicy.document: " + helpers_1.stringifyPolicy((_a = bucket === null || bucket === void 0 ? void 0 : bucket.policy) === null || _a === void 0 ? void 0 : _a.document));
    const k9BucketPolicyProps = {
        bucket: bucket,
        k9DesiredAccess: new Array({
            accessCapabilities: k9policy_1.AccessCapability.AdministerResource,
            allowPrincipalArns: administerResourceArns,
        }, {
            accessCapabilities: k9policy_1.AccessCapability.DeleteData,
            allowPrincipalArns: deleteDataArns,
        })
    };
    let addToResourcePolicyResults = k9.s3.grantAccessViaResourcePolicy(stack, "AutoDeleteBucket", k9BucketPolicyProps);
    expect(bucket.policy).toStrictEqual(originalBucketPolicy);
    assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults);
    console.log("k9 bucket policy: " + helpers_1.stringifyPolicy((_b = bucket.policy) === null || _b === void 0 ? void 0 : _b.document));
    expect(assert_1.SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
});
describe('K9KeyPolicy', () => {
    const desiredAccess = new Array({
        accessCapabilities: [
            k9policy_1.AccessCapability.AdministerResource,
            k9policy_1.AccessCapability.ReadConfig
        ],
        allowPrincipalArns: administerResourceArns,
    }, {
        accessCapabilities: k9policy_1.AccessCapability.WriteData,
        allowPrincipalArns: writeDataArns,
    }, {
        accessCapabilities: k9policy_1.AccessCapability.ReadData,
        allowPrincipalArns: readDataArns,
    }, {
        accessCapabilities: k9policy_1.AccessCapability.DeleteData,
        allowPrincipalArns: deleteDataArns,
    });
    test('Without Allow root user and Identity policies', () => {
        const stack = new cdk.Stack(app, 'WithoutRootAndIdentityPolicies');
        const k9KeyPolicyProps = {
            k9DesiredAccess: desiredAccess
        };
        expect(k9KeyPolicyProps.trustAccountIdentities).toBeFalsy();
        const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);
        let policyJsonStr = helpers_1.stringifyPolicy(keyPolicy);
        console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
        let policyObj = JSON.parse(policyJsonStr);
        let actualPolicyStatements = policyObj['Statement'];
        expect(actualPolicyStatements).toBeDefined();
        let denyEveryoneElseStmt;
        let allowRootStmt;
        for (let stmt of actualPolicyStatements) {
            if (kms_1.SID_DENY_EVERYONE_ELSE == stmt.Sid) {
                denyEveryoneElseStmt = stmt;
            }
            else if (kms_1.SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid) {
                allowRootStmt = stmt;
            }
        }
        expect(denyEveryoneElseStmt).toBeFalsy();
        expect(allowRootStmt).toBeFalsy();
        new kms.Key(stack, 'TestKeyNoRoot', { policy: keyPolicy });
        assert_1.expect(stack).to(assert_1.haveResource("AWS::KMS::Key"));
        expect(assert_1.SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
    });
    test('Allow root user and Identity policies', () => {
        const stack = new cdk.Stack(app, 'WithRootAndIdentityPolicies');
        const k9KeyPolicyProps = {
            k9DesiredAccess: desiredAccess,
            trustAccountIdentities: true
        };
        expect(k9KeyPolicyProps.trustAccountIdentities).toBeTruthy();
        const keyPolicy = k9.kms.makeKeyPolicy(k9KeyPolicyProps);
        let policyJsonStr = helpers_1.stringifyPolicy(keyPolicy);
        console.log(`keyPolicy.document (trustAccountIdentities: ${k9KeyPolicyProps.trustAccountIdentities}): ${policyJsonStr}`);
        let policyObj = JSON.parse(policyJsonStr);
        let actualPolicyStatements = policyObj['Statement'];
        expect(actualPolicyStatements).toBeDefined();
        let denyEveryoneElseStmt;
        let allowRootStmt;
        for (let stmt of actualPolicyStatements) {
            if (kms_1.SID_DENY_EVERYONE_ELSE == stmt.Sid) {
                denyEveryoneElseStmt = stmt;
            }
            else if (kms_1.SID_ALLOW_ROOT_AND_IDENTITY_POLICIES == stmt.Sid) {
                allowRootStmt = stmt;
            }
        }
        expect(denyEveryoneElseStmt).toBeTruthy();
        expect(allowRootStmt).toBeTruthy();
        new kms.Key(stack, 'TestKeyAllowRoot', { policy: keyPolicy });
        assert_1.expect(stack).to(assert_1.haveResource("AWS::KMS::Key"));
        expect(assert_1.SynthUtils.toCloudFormation(stack)).toMatchSnapshot();
    });
    test('Unmanageable key policy is rejected', () => {
        const unmanageableCapabilityCombos = [
            [],
            [k9policy_1.AccessCapability.AdministerResource],
            [k9policy_1.AccessCapability.ReadConfig],
            [k9policy_1.AccessCapability.AdministerResource, k9policy_1.AccessCapability.WriteData]
        ];
        for (let trustAccountIdentities of [true, false]) {
            for (let unmanageableAccessCapabilities of unmanageableCapabilityCombos) {
                let desiredAccess = new Array({
                    accessCapabilities: unmanageableAccessCapabilities,
                    allowPrincipalArns: administerResourceArns,
                });
                let k9KeyPolicyProps = {
                    k9DesiredAccess: desiredAccess,
                    trustAccountIdentities: true
                };
                expect(() => k9.kms.makeKeyPolicy(k9KeyPolicyProps))
                    .toThrow(/At least one principal must be able to administer and read-config for keys/);
            }
        }
    });
});
function assertContainsStatementWithId(expectStmtId, statements) {
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
function assertK9StatementsAddedToS3ResourcePolicy(addToResourcePolicyResults, k9BucketPolicyProps) {
    let numExpectedStatements = 9;
    if (k9BucketPolicyProps && k9BucketPolicyProps.publicReadAccess) {
        numExpectedStatements += 1;
    }
    expect(addToResourcePolicyResults.length).toEqual(numExpectedStatements);
    for (let result of addToResourcePolicyResults) {
        expect(result.statementAdded).toBeTruthy();
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiazkudGVzdC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIms5LnRlc3QudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSw0Q0FBOEU7QUFDOUUscUNBQXFDO0FBQ3JDLHdDQUE0QztBQUM1Qyx3Q0FBd0M7QUFDeEMsc0NBQXNDO0FBQ3RDLDRDQUFpRDtBQUNqRCw4Q0FBNkQ7QUFDN0Qsa0NBQW1IO0FBQ25ILG9DQUEwRztBQUMxRyw2QkFBNkI7QUFFN0IsdUNBQTBDO0FBRTFDLDhDQUE4QztBQUU5QyxNQUFNLHNCQUFzQixHQUFHO0lBQzNCLG1DQUFtQztDQUN0QyxDQUFDO0FBRUYsTUFBTSxhQUFhLEdBQUc7SUFDbEIsNENBQTRDO0NBQy9DLENBQUM7QUFFRixNQUFNLFlBQVksR0FBRyxhQUFhLENBQUMsTUFBTSxDQUNyQyxDQUFDLGlEQUFpRCxDQUFDLENBQ3RELENBQUM7QUFFRixNQUFNLGNBQWMsR0FBRztJQUNuQiw0Q0FBNEM7Q0FDL0MsQ0FBQztBQUVGLE1BQU0sR0FBRyxHQUFHLElBQUksR0FBRyxDQUFDLEdBQUcsRUFBRSxDQUFDO0FBRTFCLElBQUksQ0FBQyxnQ0FBZ0MsRUFBRSxHQUFHLEVBQUU7O0lBQ3hDLE1BQU0sS0FBSyxHQUFHLElBQUksR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsMEJBQTBCLENBQUMsQ0FBQztJQUM3RCxNQUFNLE1BQU0sR0FBRyxJQUFJLEVBQUUsQ0FBQyxNQUFNLENBQUMsS0FBSyxFQUFFLFlBQVksRUFBRSxFQUFFLENBQUMsQ0FBQztJQUV0RCxNQUFNLG1CQUFtQixHQUF3QjtRQUM3QyxNQUFNLEVBQUUsTUFBTTtRQUNkLGVBQWUsRUFBRSxJQUFJLEtBQUssQ0FDdEI7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7WUFDdkQsa0JBQWtCLEVBQUUsc0JBQXNCO1NBQzdDLEVBQ0Q7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxTQUFTO1lBQzlDLGtCQUFrQixFQUFFLGFBQWE7U0FDcEMsRUFDRDtZQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLFFBQVE7WUFDN0Msa0JBQWtCLEVBQUUsWUFBWTtTQUNuQyxFQUNEO1lBQ0ksa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsVUFBVTtZQUMvQyxrQkFBa0IsRUFBRSxjQUFjO1NBQ3JDLENBQ0o7S0FDSixDQUFDO0lBQ0YsSUFBSSwwQkFBMEIsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLDRCQUE0QixDQUFDLEtBQUssRUFBRSxVQUFVLEVBQUUsbUJBQW1CLENBQUMsQ0FBQztJQUM1RyxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRXBDLElBQUksU0FBUyxHQUFHLHlCQUFlLE9BQUMsTUFBTSxDQUFDLE1BQU0sMENBQUUsUUFBUSxDQUFDLENBQUM7SUFDekQsT0FBTyxDQUFDLEdBQUcsQ0FBQywyQkFBMkIsR0FBRyxTQUFTLENBQUMsQ0FBQztJQUNyRCxNQUFNLE9BQUMsTUFBTSxDQUFDLE1BQU0sMENBQUUsUUFBUSxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7SUFFOUMseUNBQXlDLENBQUMsMEJBQTBCLENBQUMsQ0FBQztJQUN0RSxJQUFJLFNBQVMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLFNBQVMsQ0FBQyxDQUFBO0lBQ3JDLElBQUksc0JBQXNCLEdBQUcsU0FBUyxDQUFDLFdBQVcsQ0FBQyxDQUFDO0lBQ3BELE1BQU0sQ0FBQyxzQkFBc0IsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRTdDLEtBQUssSUFBSSxJQUFJLElBQUksc0JBQXNCLEVBQUU7UUFDckMsSUFBRywwQ0FBcUMsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFDO1lBQ2pELE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLGlCQUFpQixDQUFDLENBQUMsaUNBQWlDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxTQUFTLENBQUMsQ0FBQztTQUNuRztLQUNKO0lBRUQsZUFBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxxQkFBWSxDQUFDLGlCQUFpQixDQUFDLENBQUMsQ0FBQztJQUNyRCxlQUFTLENBQUMsS0FBSyxDQUFDLENBQUMsRUFBRSxDQUFDLHFCQUFZLENBQUMsdUJBQXVCLENBQUMsQ0FBQyxDQUFDO0lBQzNELE1BQU0sQ0FBQyxtQkFBVSxDQUFDLGdCQUFnQixDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsZUFBZSxFQUFFLENBQUM7QUFDakUsQ0FBQyxDQUFDLENBQUM7QUFFSCxJQUFJLENBQUMsa0RBQWtELEVBQUUsR0FBRyxFQUFFOztJQUMxRCxNQUFNLEtBQUssR0FBRyxJQUFJLEdBQUcsQ0FBQyxLQUFLLENBQUMsR0FBRyxFQUFFLHVDQUF1QyxDQUFDLENBQUM7SUFDMUUsTUFBTSxNQUFNLEdBQUcsSUFBSSxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssRUFBRSxtQ0FBbUMsRUFBRSxFQUFFLENBQUMsQ0FBQztJQUU3RSxNQUFNLG1CQUFtQixHQUF3QjtRQUM3QyxNQUFNLEVBQUUsTUFBTTtRQUNkLGVBQWUsRUFBRSxJQUFJLEtBQUssQ0FDdEI7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7WUFDdkQsa0JBQWtCLEVBQUUsc0JBQXNCO1NBQzdDLENBQ0o7UUFDRCxVQUFVLEVBQUUseUJBQWdCLENBQUMsR0FBRztLQUNuQyxDQUFDO0lBQ0YsSUFBSSwwQkFBMEIsR0FBRyxFQUFFLENBQUMsRUFBRSxDQUFDLDRCQUE0QixDQUFDLEtBQUssRUFBRSxxQ0FBcUMsRUFBRSxtQkFBbUIsQ0FBQyxDQUFDO0lBQ3ZJLE1BQU0sQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7SUFFcEMsSUFBSSxTQUFTLEdBQUcseUJBQWUsT0FBQyxNQUFNLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsQ0FBQztJQUN6RCxPQUFPLENBQUMsR0FBRyxDQUFDLDJCQUEyQixHQUFHLFNBQVMsQ0FBQyxDQUFDO0lBQ3JELE1BQU0sT0FBQyxNQUFNLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUU5Qyx5Q0FBeUMsQ0FBQywwQkFBMEIsQ0FBQyxDQUFDO0lBQ3RFLElBQUksU0FBUyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsU0FBUyxDQUFDLENBQUE7SUFDckMsSUFBSSxzQkFBc0IsR0FBRyxTQUFTLENBQUMsV0FBVyxDQUFDLENBQUM7SUFDcEQsTUFBTSxDQUFDLHNCQUFzQixDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7SUFFN0MsS0FBSyxJQUFJLElBQUksSUFBSSxzQkFBc0IsRUFBRTtRQUNyQyxJQUFHLDBDQUFxQyxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUM7WUFDakQsTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUMsQ0FBQyxpQ0FBaUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLFNBQVMsQ0FBQyxDQUFDO1NBQ25HO0tBQ0o7QUFFTCxDQUFDLENBQUMsQ0FBQTtBQUVGLElBQUksQ0FBQyx5REFBeUQsRUFBRSxHQUFHLEVBQUU7O0lBQ2pFLE1BQU0sS0FBSyxHQUFHLElBQUksR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUseUNBQXlDLENBQUMsQ0FBQztJQUM1RSxNQUFNLE1BQU0sR0FBRyxJQUFJLEVBQUUsQ0FBQyxNQUFNLENBQUMsS0FBSyxFQUFFLHlDQUF5QyxFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBRW5GLE1BQU0sbUJBQW1CLEdBQXdCO1FBQzdDLE1BQU0sRUFBRSxNQUFNO1FBQ2QsZUFBZSxFQUFFLElBQUksS0FBSyxDQUN0QjtZQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLGtCQUFrQjtZQUN2RCxrQkFBa0IsRUFBRSxzQkFBc0I7U0FDN0MsQ0FDSjtRQUNELFVBQVUsRUFBRSx5QkFBZ0IsQ0FBQyxVQUFVO0tBQzFDLENBQUM7SUFDRixJQUFJLDBCQUEwQixHQUFHLEVBQUUsQ0FBQyxFQUFFLENBQUMsNEJBQTRCLENBQUMsS0FBSyxFQUFFLDJDQUEyQyxFQUFFLG1CQUFtQixDQUFDLENBQUM7SUFDN0ksTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUVwQyxJQUFJLFNBQVMsR0FBRyx5QkFBZSxPQUFDLE1BQU0sQ0FBQyxNQUFNLDBDQUFFLFFBQVEsQ0FBQyxDQUFDO0lBQ3pELE9BQU8sQ0FBQyxHQUFHLENBQUMsMkJBQTJCLEdBQUcsU0FBUyxDQUFDLENBQUM7SUFDckQsTUFBTSxPQUFDLE1BQU0sQ0FBQyxNQUFNLDBDQUFFLFFBQVEsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRTlDLHlDQUF5QyxDQUFDLDBCQUEwQixDQUFDLENBQUM7SUFDdEUsSUFBSSxTQUFTLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQTtJQUNyQyxJQUFJLHNCQUFzQixHQUFHLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUNwRCxNQUFNLENBQUMsc0JBQXNCLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUU3QyxLQUFLLElBQUksSUFBSSxJQUFJLHNCQUFzQixFQUFFO1FBQ3JDLElBQUcsMENBQXFDLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBQztZQUNqRCxNQUFNLENBQUMsSUFBSSxDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLGlDQUFpQyxDQUFDLENBQUMsQ0FBQyxPQUFPLENBQUMsUUFBUSxDQUFDLENBQUM7U0FDbEc7S0FDSjtBQUVMLENBQUMsQ0FBQyxDQUFDO0FBRUgsc0dBQXNHO0FBQ3RHLDBDQUEwQztBQUMxQyxJQUFJLENBQUMsaUdBQWlHLEVBQUUsR0FBRyxFQUFFOztJQUN6RyxNQUFNLEtBQUssR0FBRyxJQUFJLEdBQUcsQ0FBQyxLQUFLLENBQUMsR0FBRyxFQUFFLDZCQUE2QixDQUFDLENBQUM7SUFDaEUsTUFBTSxNQUFNLEdBQUcsSUFBSSxFQUFFLENBQUMsTUFBTSxDQUFDLEtBQUssRUFBRSw0QkFBNEIsRUFBRSxFQUFFLENBQUMsQ0FBQztJQUV0RSxNQUFNLG1CQUFtQixHQUF3QjtRQUM3QyxNQUFNLEVBQUUsTUFBTTtRQUNkLGVBQWUsRUFBRSxJQUFJLEtBQUssQ0FDdEI7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7WUFDdkQsa0JBQWtCLEVBQUUsc0JBQXNCO1NBQzdDLENBQ0o7UUFDRCxVQUFVLEVBQUUseUJBQWdCLENBQUMsVUFBVTtRQUN2QyxnQkFBZ0IsRUFBRSxJQUFJO0tBQ3pCLENBQUM7SUFFRixJQUFJLDBCQUEwQixHQUFHLEVBQUUsQ0FBQyxFQUFFLENBQUMsNEJBQTRCLENBQUMsS0FBSyxFQUFFLDhCQUE4QixFQUFFLG1CQUFtQixDQUFDLENBQUM7SUFDaEksTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUVwQyxJQUFJLFNBQVMsR0FBRyx5QkFBZSxPQUFDLE1BQU0sQ0FBQyxNQUFNLDBDQUFFLFFBQVEsQ0FBQyxDQUFDO0lBQ3pELE9BQU8sQ0FBQyxHQUFHLENBQUMsMkJBQTJCLEdBQUcsU0FBUyxDQUFDLENBQUM7SUFDckQsTUFBTSxPQUFDLE1BQU0sQ0FBQyxNQUFNLDBDQUFFLFFBQVEsQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRTlDLHlDQUF5QyxDQUFDLDBCQUEwQixFQUFFLG1CQUFtQixDQUFDLENBQUM7SUFDM0YsSUFBSSxTQUFTLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxTQUFTLENBQUMsQ0FBQTtJQUNyQyxJQUFJLHNCQUFzQixHQUFHLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUNwRCxNQUFNLENBQUMsc0JBQXNCLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUU3Qyw2QkFBNkIsQ0FBQyxpQ0FBNEIsRUFBRSxzQkFBc0IsQ0FBQyxDQUFDO0lBRXBGLEtBQUssSUFBSSxJQUFJLElBQUksc0JBQXNCLEVBQUU7UUFDckMsSUFBRyxpQ0FBNEIsSUFBSSxJQUFJLENBQUMsR0FBRyxFQUFDO1lBQ3hDLE1BQU0sQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUMsS0FBSyxFQUFFLEdBQUcsRUFBQyxDQUFDLENBQUE7WUFDNUMsTUFBTSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLENBQUE7U0FDOUM7YUFBTSxJQUFHLDBDQUFxQyxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUM7WUFDeEQsTUFBTSxDQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsaUJBQWlCLENBQUMsQ0FBQyxpQ0FBaUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLFFBQVEsQ0FBQyxDQUFDO1NBQ2xHO0tBQ0o7QUFFTCxDQUFDLENBQUMsQ0FBQztBQUVILElBQUksQ0FBQyxzREFBc0QsRUFBRSxHQUFHLEVBQUU7O0lBQzlELE1BQU0sVUFBVSxHQUFHLElBQUksR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsK0JBQStCLENBQUMsQ0FBQztJQUN2RSxNQUFNLE1BQU0sR0FBRyxJQUFJLEVBQUUsQ0FBQyxNQUFNLENBQUMsVUFBVSxFQUFFLCtCQUErQixFQUFFLEVBQUUsQ0FBQyxDQUFDO0lBRTlFLE1BQU0sbUJBQW1CLEdBQXdCO1FBQzdDLE1BQU0sRUFBRSxNQUFNO1FBQ2QsZUFBZSxFQUFFLElBQUksS0FBSyxDQUN0QjtZQUNJLGtCQUFrQixFQUFFO2dCQUNoQiwyQkFBZ0IsQ0FBQyxrQkFBa0I7Z0JBQ25DLDJCQUFnQixDQUFDLFVBQVU7YUFDOUI7WUFDRCxrQkFBa0IsRUFBRSxzQkFBc0I7U0FDN0MsRUFDRDtZQUNJLGtCQUFrQixFQUFFO2dCQUNoQiwyQkFBZ0IsQ0FBQyxRQUFRO2dCQUN6QiwyQkFBZ0IsQ0FBQyxTQUFTO2dCQUMxQiwyQkFBZ0IsQ0FBQyxVQUFVO2FBQzlCO1lBQ0Qsa0JBQWtCLEVBQUUsYUFBYTtTQUNwQyxDQUNKO0tBQ0osQ0FBQztJQUNGLElBQUksMEJBQTBCLEdBQUcsRUFBRSxDQUFDLEVBQUUsQ0FBQyw0QkFBNEIsQ0FBQyxVQUFVLEVBQUUseUJBQXlCLEVBQUUsbUJBQW1CLENBQUMsQ0FBQztJQUNoSSxNQUFNLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLFdBQVcsRUFBRSxDQUFDO0lBRXBDLE9BQU8sQ0FBQyxHQUFHLENBQUMsMkJBQTJCLEdBQUcseUJBQWUsT0FBQyxNQUFNLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsQ0FBQyxDQUFDO0lBQ3BGLE1BQU0sT0FBQyxNQUFNLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztJQUU5Qyx5Q0FBeUMsQ0FBQywwQkFBMEIsQ0FBQyxDQUFDO0lBRXRFLGVBQVMsQ0FBQyxVQUFVLENBQUMsQ0FBQyxFQUFFLENBQUMscUJBQVksQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDLENBQUM7SUFDMUQsZUFBUyxDQUFDLFVBQVUsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxxQkFBWSxDQUFDLHVCQUF1QixDQUFDLENBQUMsQ0FBQztJQUNoRSxNQUFNLENBQUMsbUJBQVUsQ0FBQyxnQkFBZ0IsQ0FBQyxVQUFVLENBQUMsQ0FBQyxDQUFDLGVBQWUsRUFBRSxDQUFDO0FBQ3RFLENBQUMsQ0FBQyxDQUFDO0FBRUgsSUFBSSxDQUFDLDZFQUE2RSxFQUFFLEdBQUcsRUFBRTs7SUFDckYsTUFBTSxLQUFLLEdBQUcsSUFBSSxHQUFHLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSx1Q0FBdUMsQ0FBQyxDQUFDO0lBQzFFLE1BQU0sTUFBTSxHQUFHLElBQUksRUFBRSxDQUFDLE1BQU0sQ0FBQyxLQUFLLEVBQUUsa0JBQWtCLEVBQUU7UUFDcEQsaUJBQWlCLEVBQUUsSUFBSTtRQUN2QixhQUFhLEVBQUUsb0JBQWEsQ0FBQyxPQUFPO0tBQ3ZDLENBQUMsQ0FBQztJQUVILElBQUksb0JBQW9CLEdBQUcsTUFBTSxDQUFDLE1BQU0sQ0FBQztJQUN6QyxNQUFNLENBQUMsb0JBQW9CLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztJQUMxQyxPQUFPLENBQUMsR0FBRyxDQUFDLGtDQUFrQyxHQUFHLHlCQUFlLE9BQUMsTUFBTSxhQUFOLE1BQU0sdUJBQU4sTUFBTSxDQUFFLE1BQU0sMENBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQztJQUU1RixNQUFNLG1CQUFtQixHQUF3QjtRQUM3QyxNQUFNLEVBQUUsTUFBTTtRQUNkLGVBQWUsRUFBRSxJQUFJLEtBQUssQ0FDdEI7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxrQkFBa0I7WUFDdkQsa0JBQWtCLEVBQUUsc0JBQXNCO1NBQzdDLEVBQ0Q7WUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxVQUFVO1lBQy9DLGtCQUFrQixFQUFFLGNBQWM7U0FDckMsQ0FDSjtLQUNKLENBQUM7SUFDRixJQUFJLDBCQUEwQixHQUFHLEVBQUUsQ0FBQyxFQUFFLENBQUMsNEJBQTRCLENBQUMsS0FBSyxFQUFFLGtCQUFrQixFQUFFLG1CQUFtQixDQUFDLENBQUM7SUFFcEgsTUFBTSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxhQUFhLENBQUMsb0JBQW9CLENBQUMsQ0FBQztJQUUxRCx5Q0FBeUMsQ0FBQywwQkFBMEIsQ0FBQyxDQUFDO0lBRXRFLE9BQU8sQ0FBQyxHQUFHLENBQUMsb0JBQW9CLEdBQUcseUJBQWUsT0FBQyxNQUFNLENBQUMsTUFBTSwwQ0FBRSxRQUFRLENBQUMsQ0FBQyxDQUFDO0lBQzdFLE1BQU0sQ0FBQyxtQkFBVSxDQUFDLGdCQUFnQixDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsZUFBZSxFQUFFLENBQUM7QUFDakUsQ0FBQyxDQUFDLENBQUM7QUFFSCxRQUFRLENBQUMsYUFBYSxFQUFFLEdBQUcsRUFBRTtJQUN6QixNQUFNLGFBQWEsR0FBRyxJQUFJLEtBQUssQ0FDM0I7UUFDSSxrQkFBa0IsRUFBRTtZQUNoQiwyQkFBZ0IsQ0FBQyxrQkFBa0I7WUFDbkMsMkJBQWdCLENBQUMsVUFBVTtTQUM5QjtRQUNELGtCQUFrQixFQUFFLHNCQUFzQjtLQUM3QyxFQUNEO1FBQ0ksa0JBQWtCLEVBQUUsMkJBQWdCLENBQUMsU0FBUztRQUM5QyxrQkFBa0IsRUFBRSxhQUFhO0tBQ3BDLEVBQ0Q7UUFDSSxrQkFBa0IsRUFBRSwyQkFBZ0IsQ0FBQyxRQUFRO1FBQzdDLGtCQUFrQixFQUFFLFlBQVk7S0FDbkMsRUFDRDtRQUNJLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLFVBQVU7UUFDL0Msa0JBQWtCLEVBQUUsY0FBYztLQUNyQyxDQUNKLENBQUM7SUFDRixJQUFJLENBQUMsK0NBQStDLEVBQUUsR0FBRyxFQUFFO1FBQ3ZELE1BQU0sS0FBSyxHQUFHLElBQUksR0FBRyxDQUFDLEtBQUssQ0FBQyxHQUFHLEVBQUUsZ0NBQWdDLENBQUMsQ0FBQztRQUNuRSxNQUFNLGdCQUFnQixHQUFxQjtZQUN2QyxlQUFlLEVBQUUsYUFBYTtTQUNqQyxDQUFDO1FBRUYsTUFBTSxDQUFDLGdCQUFnQixDQUFDLHNCQUFzQixDQUFDLENBQUMsU0FBUyxFQUFFLENBQUM7UUFDNUQsTUFBTSxTQUFTLEdBQUcsRUFBRSxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztRQUV6RCxJQUFJLGFBQWEsR0FBRyx5QkFBZSxDQUFDLFNBQVMsQ0FBQyxDQUFDO1FBQy9DLE9BQU8sQ0FBQyxHQUFHLENBQUMsK0NBQStDLGdCQUFnQixDQUFDLHNCQUFzQixNQUFNLGFBQWEsRUFBRSxDQUFDLENBQUM7UUFDekgsSUFBSSxTQUFTLEdBQUcsSUFBSSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsQ0FBQztRQUUxQyxJQUFJLHNCQUFzQixHQUFHLFNBQVMsQ0FBQyxXQUFXLENBQUMsQ0FBQztRQUNwRCxNQUFNLENBQUMsc0JBQXNCLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQztRQUU3QyxJQUFJLG9CQUF5QixDQUFDO1FBQzlCLElBQUksYUFBa0IsQ0FBQztRQUN2QixLQUFLLElBQUksSUFBSSxJQUFJLHNCQUFzQixFQUFFO1lBQ3JDLElBQUcsNEJBQXNCLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBQztnQkFDbEMsb0JBQW9CLEdBQUcsSUFBSSxDQUFDO2FBQy9CO2lCQUFNLElBQUcsMENBQW9DLElBQUksSUFBSSxDQUFDLEdBQUcsRUFBQztnQkFDdkQsYUFBYSxHQUFHLElBQUksQ0FBQzthQUN4QjtTQUNKO1FBRUQsTUFBTSxDQUFDLG9CQUFvQixDQUFDLENBQUMsU0FBUyxFQUFFLENBQUM7UUFDekMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxDQUFDLFNBQVMsRUFBRSxDQUFDO1FBRWxDLElBQUksR0FBRyxDQUFDLEdBQUcsQ0FBQyxLQUFLLEVBQUUsZUFBZSxFQUFFLEVBQUMsTUFBTSxFQUFFLFNBQVMsRUFBQyxDQUFDLENBQUM7UUFFekQsZUFBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxxQkFBWSxDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUM7UUFDbkQsTUFBTSxDQUFDLG1CQUFVLENBQUMsZ0JBQWdCLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxlQUFlLEVBQUUsQ0FBQztJQUNqRSxDQUFDLENBQUMsQ0FBQztJQUVILElBQUksQ0FBQyx1Q0FBdUMsRUFBRSxHQUFHLEVBQUU7UUFDL0MsTUFBTSxLQUFLLEdBQUcsSUFBSSxHQUFHLENBQUMsS0FBSyxDQUFDLEdBQUcsRUFBRSw2QkFBNkIsQ0FBQyxDQUFDO1FBQ2hFLE1BQU0sZ0JBQWdCLEdBQXFCO1lBQ3ZDLGVBQWUsRUFBRSxhQUFhO1lBQzlCLHNCQUFzQixFQUFFLElBQUk7U0FDL0IsQ0FBQztRQUVGLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FBQyxzQkFBc0IsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQzdELE1BQU0sU0FBUyxHQUFHLEVBQUUsQ0FBQyxHQUFHLENBQUMsYUFBYSxDQUFDLGdCQUFnQixDQUFDLENBQUM7UUFFekQsSUFBSSxhQUFhLEdBQUcseUJBQWUsQ0FBQyxTQUFTLENBQUMsQ0FBQztRQUMvQyxPQUFPLENBQUMsR0FBRyxDQUFDLCtDQUErQyxnQkFBZ0IsQ0FBQyxzQkFBc0IsTUFBTSxhQUFhLEVBQUUsQ0FBQyxDQUFDO1FBQ3pILElBQUksU0FBUyxHQUFHLElBQUksQ0FBQyxLQUFLLENBQUMsYUFBYSxDQUFDLENBQUM7UUFFMUMsSUFBSSxzQkFBc0IsR0FBRyxTQUFTLENBQUMsV0FBVyxDQUFDLENBQUM7UUFDcEQsTUFBTSxDQUFDLHNCQUFzQixDQUFDLENBQUMsV0FBVyxFQUFFLENBQUM7UUFFN0MsSUFBSSxvQkFBeUIsQ0FBQztRQUM5QixJQUFJLGFBQWtCLENBQUM7UUFDdkIsS0FBSyxJQUFJLElBQUksSUFBSSxzQkFBc0IsRUFBRTtZQUNyQyxJQUFHLDRCQUFzQixJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUM7Z0JBQ2xDLG9CQUFvQixHQUFHLElBQUksQ0FBQzthQUMvQjtpQkFBTSxJQUFHLDBDQUFvQyxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUM7Z0JBQ3ZELGFBQWEsR0FBRyxJQUFJLENBQUM7YUFDeEI7U0FDSjtRQUVELE1BQU0sQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO1FBQzFDLE1BQU0sQ0FBQyxhQUFhLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztRQUduQyxJQUFJLEdBQUcsQ0FBQyxHQUFHLENBQUMsS0FBSyxFQUFFLGtCQUFrQixFQUFFLEVBQUMsTUFBTSxFQUFFLFNBQVMsRUFBQyxDQUFDLENBQUM7UUFFNUQsZUFBUyxDQUFDLEtBQUssQ0FBQyxDQUFDLEVBQUUsQ0FBQyxxQkFBWSxDQUFDLGVBQWUsQ0FBQyxDQUFDLENBQUM7UUFDbkQsTUFBTSxDQUFDLG1CQUFVLENBQUMsZ0JBQWdCLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxlQUFlLEVBQUUsQ0FBQztJQUNqRSxDQUFDLENBQUMsQ0FBQztJQUVILElBQUksQ0FBQyxxQ0FBcUMsRUFBRSxHQUFHLEVBQUU7UUFFN0MsTUFBTSw0QkFBNEIsR0FBRztZQUNuQyxFQUFFO1lBQ0YsQ0FBQywyQkFBZ0IsQ0FBQyxrQkFBa0IsQ0FBQztZQUNyQyxDQUFDLDJCQUFnQixDQUFDLFVBQVUsQ0FBQztZQUM3QixDQUFDLDJCQUFnQixDQUFDLGtCQUFrQixFQUFFLDJCQUFnQixDQUFDLFNBQVMsQ0FBQztTQUNsRSxDQUFDO1FBRUYsS0FBSSxJQUFJLHNCQUFzQixJQUFJLENBQUMsSUFBSSxFQUFFLEtBQUssQ0FBQyxFQUFDO1lBQzVDLEtBQUksSUFBSSw4QkFBOEIsSUFBSSw0QkFBNEIsRUFBQztnQkFDbkUsSUFBSSxhQUFhLEdBQUcsSUFBSSxLQUFLLENBQ3pCO29CQUNJLGtCQUFrQixFQUFFLDhCQUE4QjtvQkFDbEQsa0JBQWtCLEVBQUUsc0JBQXNCO2lCQUM3QyxDQUNKLENBQUM7Z0JBRUYsSUFBSSxnQkFBZ0IsR0FBcUI7b0JBQ3JDLGVBQWUsRUFBRSxhQUFhO29CQUM5QixzQkFBc0IsRUFBRSxJQUFJO2lCQUMvQixDQUFDO2dCQUVGLE1BQU0sQ0FBQyxHQUFHLEVBQUUsQ0FBQyxFQUFFLENBQUMsR0FBRyxDQUFDLGFBQWEsQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO3FCQUMvQyxPQUFPLENBQUMsNEVBQTRFLENBQUMsQ0FBQTthQUU3RjtTQUVKO0lBQ0wsQ0FBQyxDQUFDLENBQUM7QUFFUCxDQUFDLENBQUMsQ0FBQztBQUVILFNBQVMsNkJBQTZCLENBQUMsWUFBbUIsRUFBRSxVQUFjO0lBQ3RFLElBQUksU0FBUyxHQUFHLEtBQUssQ0FBQztJQUN0QixPQUFPLENBQUMsR0FBRyxDQUFDLDZCQUE2QixZQUFZLEVBQUUsQ0FBQyxDQUFBO0lBQ3hELEtBQUssSUFBSSxJQUFJLElBQUksVUFBVSxFQUFFO1FBQ3pCLElBQUcsWUFBWSxJQUFJLElBQUksQ0FBQyxHQUFHLEVBQUM7WUFDMUIsU0FBUyxHQUFHLElBQUksQ0FBQztZQUNqQixNQUFNO1NBQ1A7S0FDSjtJQUNELE1BQU0sQ0FBQyxTQUFTLENBQUMsQ0FBQyxVQUFVLEVBQUUsQ0FBQztBQUNuQyxDQUFDO0FBRUQsU0FBUyx5Q0FBeUMsQ0FBQywwQkFBdUQsRUFBRSxtQkFBeUM7SUFDakosSUFBSSxxQkFBcUIsR0FBRyxDQUFDLENBQUM7SUFDOUIsSUFBRyxtQkFBbUIsSUFBSSxtQkFBbUIsQ0FBQyxnQkFBZ0IsRUFBQztRQUMzRCxxQkFBcUIsSUFBSSxDQUFDLENBQUM7S0FDOUI7SUFDRCxNQUFNLENBQUMsMEJBQTBCLENBQUMsTUFBTSxDQUFDLENBQUMsT0FBTyxDQUFDLHFCQUFxQixDQUFDLENBQUM7SUFDekUsS0FBSyxJQUFJLE1BQU0sSUFBSSwwQkFBMEIsRUFBRTtRQUMzQyxNQUFNLENBQUMsTUFBTSxDQUFDLGNBQWMsQ0FBQyxDQUFDLFVBQVUsRUFBRSxDQUFDO0tBQzlDO0FBQ0wsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7ZXhwZWN0IGFzIGV4cGVjdENESywgaGF2ZVJlc291cmNlLCBTeW50aFV0aWxzfSBmcm9tICdAYXdzLWNkay9hc3NlcnQnO1xuaW1wb3J0ICogYXMgY2RrIGZyb20gJ0Bhd3MtY2RrL2NvcmUnO1xuaW1wb3J0IHtSZW1vdmFsUG9saWN5fSBmcm9tICdAYXdzLWNkay9jb3JlJztcbmltcG9ydCAqIGFzIGttcyBmcm9tICdAYXdzLWNkay9hd3Mta21zJztcbmltcG9ydCAqIGFzIHMzIGZyb20gJ0Bhd3MtY2RrL2F3cy1zMyc7XG5pbXBvcnQge0J1Y2tldEVuY3J5cHRpb259IGZyb20gJ0Bhd3MtY2RrL2F3cy1zMyc7XG5pbXBvcnQge0FjY2Vzc0NhcGFiaWxpdHksIEFjY2Vzc1NwZWN9IGZyb20gJy4uL2xpYi9rOXBvbGljeSc7XG5pbXBvcnQge0s5QnVja2V0UG9saWN5UHJvcHMsIFNJRF9BTExPV19QVUJMSUNfUkVBRF9BQ0NFU1MsIFNJRF9ERU5ZX1VORVhQRUNURURfRU5DUllQVElPTl9NRVRIT0R9IGZyb20gXCIuLi9saWIvczNcIjtcbmltcG9ydCB7SzlLZXlQb2xpY3lQcm9wcywgU0lEX0FMTE9XX1JPT1RfQU5EX0lERU5USVRZX1BPTElDSUVTLCBTSURfREVOWV9FVkVSWU9ORV9FTFNFfSBmcm9tIFwiLi4vbGliL2ttc1wiO1xuaW1wb3J0ICogYXMgazkgZnJvbSBcIi4uL2xpYlwiO1xuaW1wb3J0IHtBZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0fSBmcm9tIFwiQGF3cy1jZGsvYXdzLWlhbVwiO1xuaW1wb3J0IHtzdHJpbmdpZnlQb2xpY3l9IGZyb20gXCIuL2hlbHBlcnNcIjtcblxuLy8gVGVzdCB0aGUgcHJpbWFyeSBwdWJsaWMgaW50ZXJmYWNlIHRvIGs5IGNka1xuXG5jb25zdCBhZG1pbmlzdGVyUmVzb3VyY2VBcm5zID0gW1xuICAgIFwiYXJuOmF3czppYW06OjEzOTcxMDQ5MTEyMDp1c2VyL2NpXCIsXG5dO1xuXG5jb25zdCB3cml0ZURhdGFBcm5zID0gW1xuICAgIFwiYXJuOmF3czppYW06OjEyMzQ1Njc4OTAxMjpyb2xlL2FwcC1iYWNrZW5kXCIsXG5dO1xuXG5jb25zdCByZWFkRGF0YUFybnMgPSB3cml0ZURhdGFBcm5zLmNvbmNhdChcbiAgICBbXCJhcm46YXdzOmlhbTo6MTIzNDU2Nzg5MDEyOnJvbGUvY3VzdG9tZXItc2VydmljZVwiXVxuKTtcblxuY29uc3QgZGVsZXRlRGF0YUFybnMgPSBbXG4gICAgXCJhcm46YXdzOmlhbTo6MTM5NzEwNDkxMTIwOnVzZXIvc3VwZXItYWRtaW5cIixcbl07XG5cbmNvbnN0IGFwcCA9IG5ldyBjZGsuQXBwKCk7XG5cbnRlc3QoJ0s5QnVja2V0UG9saWN5IC0gdHlwaWNhbCB1c2FnZScsICgpID0+IHtcbiAgICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soYXBwLCAnSzlQb2xpY3lUZXN0VHlwaWNhbFVzYWdlJyk7XG4gICAgY29uc3QgYnVja2V0ID0gbmV3IHMzLkJ1Y2tldChzdGFjaywgJ1Rlc3RCdWNrZXQnLCB7fSk7XG5cbiAgICBjb25zdCBrOUJ1Y2tldFBvbGljeVByb3BzOiBLOUJ1Y2tldFBvbGljeVByb3BzID0ge1xuICAgICAgICBidWNrZXQ6IGJ1Y2tldCxcbiAgICAgICAgazlEZXNpcmVkQWNjZXNzOiBuZXcgQXJyYXk8QWNjZXNzU3BlYz4oXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZSxcbiAgICAgICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IGFkbWluaXN0ZXJSZXNvdXJjZUFybnMsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5Xcml0ZURhdGEsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiB3cml0ZURhdGFBcm5zLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGEsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiByZWFkRGF0YUFybnMsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5EZWxldGVEYXRhLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogZGVsZXRlRGF0YUFybnMsXG4gICAgICAgICAgICB9LFxuICAgICAgICApXG4gICAgfTtcbiAgICBsZXQgYWRkVG9SZXNvdXJjZVBvbGljeVJlc3VsdHMgPSBrOS5zMy5ncmFudEFjY2Vzc1ZpYVJlc291cmNlUG9saWN5KHN0YWNrLCBcIlMzQnVja2V0XCIsIGs5QnVja2V0UG9saWN5UHJvcHMpO1xuICAgIGV4cGVjdChidWNrZXQucG9saWN5KS50b0JlRGVmaW5lZCgpO1xuXG4gICAgbGV0IHBvbGljeVN0ciA9IHN0cmluZ2lmeVBvbGljeShidWNrZXQucG9saWN5Py5kb2N1bWVudCk7XG4gICAgY29uc29sZS5sb2coXCJidWNrZXQucG9saWN5Py5kb2N1bWVudDogXCIgKyBwb2xpY3lTdHIpO1xuICAgIGV4cGVjdChidWNrZXQucG9saWN5Py5kb2N1bWVudCkudG9CZURlZmluZWQoKTtcblxuICAgIGFzc2VydEs5U3RhdGVtZW50c0FkZGVkVG9TM1Jlc291cmNlUG9saWN5KGFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHRzKTtcbiAgICBsZXQgcG9saWN5T2JqID0gSlNPTi5wYXJzZShwb2xpY3lTdHIpXG4gICAgbGV0IGFjdHVhbFBvbGljeVN0YXRlbWVudHMgPSBwb2xpY3lPYmpbJ1N0YXRlbWVudCddO1xuICAgIGV4cGVjdChhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKS50b0JlRGVmaW5lZCgpO1xuXG4gICAgZm9yIChsZXQgc3RtdCBvZiBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKSB7XG4gICAgICAgIGlmKFNJRF9ERU5ZX1VORVhQRUNURURfRU5DUllQVElPTl9NRVRIT0QgPT0gc3RtdC5TaWQpe1xuICAgICAgICAgICAgZXhwZWN0KHN0bXQuQ29uZGl0aW9uWydTdHJpbmdOb3RFcXVhbHMnXVsnczM6eC1hbXotc2VydmVyLXNpZGUtZW5jcnlwdGlvbiddKS50b0VxdWFsKCdhd3M6a21zJyk7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICBleHBlY3RDREsoc3RhY2spLnRvKGhhdmVSZXNvdXJjZShcIkFXUzo6UzM6OkJ1Y2tldFwiKSk7XG4gICAgZXhwZWN0Q0RLKHN0YWNrKS50byhoYXZlUmVzb3VyY2UoXCJBV1M6OlMzOjpCdWNrZXRQb2xpY3lcIikpO1xuICAgIGV4cGVjdChTeW50aFV0aWxzLnRvQ2xvdWRGb3JtYXRpb24oc3RhY2spKS50b01hdGNoU25hcHNob3QoKTtcbn0pO1xuXG50ZXN0KCdLOUJ1Y2tldFBvbGljeSAtIHNwZWNpZnkgZW5jcnlwdGlvbiBtZXRob2QgLSBLTVMnLCAoKSA9PiB7XG4gICAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKGFwcCwgJ0s5QnVja2V0UG9saWN5V2l0aEVuY3J5cHRpb25NZXRob2RLTVMnKTtcbiAgICBjb25zdCBidWNrZXQgPSBuZXcgczMuQnVja2V0KHN0YWNrLCAnVGVzdEJ1Y2tldFdpdGhFbmNyeXB0aW9uTWV0aG9kS01TJywge30pO1xuXG4gICAgY29uc3QgazlCdWNrZXRQb2xpY3lQcm9wczogSzlCdWNrZXRQb2xpY3lQcm9wcyA9IHtcbiAgICAgICAgYnVja2V0OiBidWNrZXQsXG4gICAgICAgIGs5RGVzaXJlZEFjY2VzczogbmV3IEFycmF5PEFjY2Vzc1NwZWM+KFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBhZG1pbmlzdGVyUmVzb3VyY2VBcm5zLFxuICAgICAgICAgICAgfVxuICAgICAgICApLFxuICAgICAgICBlbmNyeXB0aW9uOiBCdWNrZXRFbmNyeXB0aW9uLktNUyxcbiAgICB9O1xuICAgIGxldCBhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cyA9IGs5LnMzLmdyYW50QWNjZXNzVmlhUmVzb3VyY2VQb2xpY3koc3RhY2ssIFwiQnVja2V0UG9saWN5V2l0aEVuY3J5cHRpb25NZXRob2RLTVNcIiwgazlCdWNrZXRQb2xpY3lQcm9wcyk7XG4gICAgZXhwZWN0KGJ1Y2tldC5wb2xpY3kpLnRvQmVEZWZpbmVkKCk7XG5cbiAgICBsZXQgcG9saWN5U3RyID0gc3RyaW5naWZ5UG9saWN5KGJ1Y2tldC5wb2xpY3k/LmRvY3VtZW50KTtcbiAgICBjb25zb2xlLmxvZyhcImJ1Y2tldC5wb2xpY3k/LmRvY3VtZW50OiBcIiArIHBvbGljeVN0cik7XG4gICAgZXhwZWN0KGJ1Y2tldC5wb2xpY3k/LmRvY3VtZW50KS50b0JlRGVmaW5lZCgpO1xuXG4gICAgYXNzZXJ0SzlTdGF0ZW1lbnRzQWRkZWRUb1MzUmVzb3VyY2VQb2xpY3koYWRkVG9SZXNvdXJjZVBvbGljeVJlc3VsdHMpO1xuICAgIGxldCBwb2xpY3lPYmogPSBKU09OLnBhcnNlKHBvbGljeVN0cilcbiAgICBsZXQgYWN0dWFsUG9saWN5U3RhdGVtZW50cyA9IHBvbGljeU9ialsnU3RhdGVtZW50J107XG4gICAgZXhwZWN0KGFjdHVhbFBvbGljeVN0YXRlbWVudHMpLnRvQmVEZWZpbmVkKCk7XG5cbiAgICBmb3IgKGxldCBzdG10IG9mIGFjdHVhbFBvbGljeVN0YXRlbWVudHMpIHtcbiAgICAgICAgaWYoU0lEX0RFTllfVU5FWFBFQ1RFRF9FTkNSWVBUSU9OX01FVEhPRCA9PSBzdG10LlNpZCl7XG4gICAgICAgICAgICBleHBlY3Qoc3RtdC5Db25kaXRpb25bJ1N0cmluZ05vdEVxdWFscyddWydzMzp4LWFtei1zZXJ2ZXItc2lkZS1lbmNyeXB0aW9uJ10pLnRvRXF1YWwoJ2F3czprbXMnKTtcbiAgICAgICAgfVxuICAgIH1cblxufSlcblxudGVzdCgnSzlCdWNrZXRQb2xpY3kgLSBzcGVjaWZ5IGVuY3J5cHRpb24gbWV0aG9kIC0gUzNfTUFOQUdFRCcsICgpID0+IHtcbiAgICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soYXBwLCAnSzlCdWNrZXRQb2xpY3lBbHRlcm5hdGVFbmNyeXB0aW9uTWV0aG9kJyk7XG4gICAgY29uc3QgYnVja2V0ID0gbmV3IHMzLkJ1Y2tldChzdGFjaywgJ1Rlc3RCdWNrZXRXaXRoQWx0ZXJuYXRlRW5jcnlwdGlvbk1ldGhvZCcsIHt9KTtcblxuICAgIGNvbnN0IGs5QnVja2V0UG9saWN5UHJvcHM6IEs5QnVja2V0UG9saWN5UHJvcHMgPSB7XG4gICAgICAgIGJ1Y2tldDogYnVja2V0LFxuICAgICAgICBrOURlc2lyZWRBY2Nlc3M6IG5ldyBBcnJheTxBY2Nlc3NTcGVjPihcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5pc3RlclJlc291cmNlQXJucyxcbiAgICAgICAgICAgIH1cbiAgICAgICAgKSxcbiAgICAgICAgZW5jcnlwdGlvbjogQnVja2V0RW5jcnlwdGlvbi5TM19NQU5BR0VELFxuICAgIH07XG4gICAgbGV0IGFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHRzID0gazkuczMuZ3JhbnRBY2Nlc3NWaWFSZXNvdXJjZVBvbGljeShzdGFjaywgXCJCdWNrZXRQb2xpY3lXaXRoQWx0ZXJuYXRlRW5jcnlwdGlvbk1ldGhvZFwiLCBrOUJ1Y2tldFBvbGljeVByb3BzKTtcbiAgICBleHBlY3QoYnVja2V0LnBvbGljeSkudG9CZURlZmluZWQoKTtcblxuICAgIGxldCBwb2xpY3lTdHIgPSBzdHJpbmdpZnlQb2xpY3koYnVja2V0LnBvbGljeT8uZG9jdW1lbnQpO1xuICAgIGNvbnNvbGUubG9nKFwiYnVja2V0LnBvbGljeT8uZG9jdW1lbnQ6IFwiICsgcG9saWN5U3RyKTtcbiAgICBleHBlY3QoYnVja2V0LnBvbGljeT8uZG9jdW1lbnQpLnRvQmVEZWZpbmVkKCk7XG5cbiAgICBhc3NlcnRLOVN0YXRlbWVudHNBZGRlZFRvUzNSZXNvdXJjZVBvbGljeShhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cyk7XG4gICAgbGV0IHBvbGljeU9iaiA9IEpTT04ucGFyc2UocG9saWN5U3RyKVxuICAgIGxldCBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzID0gcG9saWN5T2JqWydTdGF0ZW1lbnQnXTtcbiAgICBleHBlY3QoYWN0dWFsUG9saWN5U3RhdGVtZW50cykudG9CZURlZmluZWQoKTtcblxuICAgIGZvciAobGV0IHN0bXQgb2YgYWN0dWFsUG9saWN5U3RhdGVtZW50cykge1xuICAgICAgICBpZihTSURfREVOWV9VTkVYUEVDVEVEX0VOQ1JZUFRJT05fTUVUSE9EID09IHN0bXQuU2lkKXtcbiAgICAgICAgICAgIGV4cGVjdChzdG10LkNvbmRpdGlvblsnU3RyaW5nTm90RXF1YWxzJ11bJ3MzOngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24nXSkudG9FcXVhbCgnQUVTMjU2Jyk7XG4gICAgICAgIH1cbiAgICB9XG5cbn0pO1xuXG4vL3B1YmxpYyBidWNrZXQgdXNlIGNhc2U6IGdlbmVyYXRlIGEgcG9saWN5IHRoYXQgc2F5cyBzc2UtczMgaXMgcmVxdWlyZWQgYW5kIHJlYWQtZGF0YSBieSBwdWJsaWMgaXMgb2tcbi8vYnV0IHdyaXRlLWRhdGEgaXMgcHJvdGVjdGVkIGZvciBleGFtcGxlLlxudGVzdCgnSzlCdWNrZXRQb2xpY3kgLSBmb3IgYSBwdWJsaWMgd2Vic2l0ZSAoZGlyZWN0IHRvIFMzKSAtIHNzZS1zMyArIHB1YmxpYy1yZWFkICsgcmVzdHJpY3RlZC13cml0ZSAnLCAoKSA9PiB7XG4gICAgY29uc3Qgc3RhY2sgPSBuZXcgY2RrLlN0YWNrKGFwcCwgJ0s5QnVja2V0UG9saWN5UHVibGljV2Vic2l0ZScpO1xuICAgIGNvbnN0IGJ1Y2tldCA9IG5ldyBzMy5CdWNrZXQoc3RhY2ssICdUZXN0QnVja2V0Rm9yUHVibGljV2Vic2l0ZScsIHt9KTtcblxuICAgIGNvbnN0IGs5QnVja2V0UG9saWN5UHJvcHM6IEs5QnVja2V0UG9saWN5UHJvcHMgPSB7XG4gICAgICAgIGJ1Y2tldDogYnVja2V0LFxuICAgICAgICBrOURlc2lyZWRBY2Nlc3M6IG5ldyBBcnJheTxBY2Nlc3NTcGVjPihcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5pc3RlclJlc291cmNlQXJucyxcbiAgICAgICAgICAgIH1cbiAgICAgICAgKSxcbiAgICAgICAgZW5jcnlwdGlvbjogQnVja2V0RW5jcnlwdGlvbi5TM19NQU5BR0VELFxuICAgICAgICBwdWJsaWNSZWFkQWNjZXNzOiB0cnVlXG4gICAgfTtcblxuICAgIGxldCBhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cyA9IGs5LnMzLmdyYW50QWNjZXNzVmlhUmVzb3VyY2VQb2xpY3koc3RhY2ssIFwiQnVja2V0UG9saWN5Rm9yUHVibGljV2Vic2l0ZVwiLCBrOUJ1Y2tldFBvbGljeVByb3BzKTtcbiAgICBleHBlY3QoYnVja2V0LnBvbGljeSkudG9CZURlZmluZWQoKTtcblxuICAgIGxldCBwb2xpY3lTdHIgPSBzdHJpbmdpZnlQb2xpY3koYnVja2V0LnBvbGljeT8uZG9jdW1lbnQpO1xuICAgIGNvbnNvbGUubG9nKFwiYnVja2V0LnBvbGljeT8uZG9jdW1lbnQ6IFwiICsgcG9saWN5U3RyKTtcbiAgICBleHBlY3QoYnVja2V0LnBvbGljeT8uZG9jdW1lbnQpLnRvQmVEZWZpbmVkKCk7XG5cbiAgICBhc3NlcnRLOVN0YXRlbWVudHNBZGRlZFRvUzNSZXNvdXJjZVBvbGljeShhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cywgazlCdWNrZXRQb2xpY3lQcm9wcyk7XG4gICAgbGV0IHBvbGljeU9iaiA9IEpTT04ucGFyc2UocG9saWN5U3RyKVxuICAgIGxldCBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzID0gcG9saWN5T2JqWydTdGF0ZW1lbnQnXTtcbiAgICBleHBlY3QoYWN0dWFsUG9saWN5U3RhdGVtZW50cykudG9CZURlZmluZWQoKTtcblxuICAgIGFzc2VydENvbnRhaW5zU3RhdGVtZW50V2l0aElkKFNJRF9BTExPV19QVUJMSUNfUkVBRF9BQ0NFU1MsIGFjdHVhbFBvbGljeVN0YXRlbWVudHMpO1xuXG4gICAgZm9yIChsZXQgc3RtdCBvZiBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKSB7XG4gICAgICAgIGlmKFNJRF9BTExPV19QVUJMSUNfUkVBRF9BQ0NFU1MgPT0gc3RtdC5TaWQpe1xuICAgICAgICAgICAgZXhwZWN0KHN0bXQuUHJpbmNpcGFsKS50b0VxdWFsKHtcIkFXU1wiOiBcIipcIn0pXG4gICAgICAgICAgICBleHBlY3Qoc3RtdC5BY3Rpb24pLnRvRXF1YWwoJ3MzOkdldE9iamVjdCcpXG4gICAgICAgIH0gZWxzZSBpZihTSURfREVOWV9VTkVYUEVDVEVEX0VOQ1JZUFRJT05fTUVUSE9EID09IHN0bXQuU2lkKXtcbiAgICAgICAgICAgIGV4cGVjdChzdG10LkNvbmRpdGlvblsnU3RyaW5nTm90RXF1YWxzJ11bJ3MzOngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24nXSkudG9FcXVhbCgnQUVTMjU2Jyk7XG4gICAgICAgIH1cbiAgICB9XG5cbn0pO1xuXG50ZXN0KCdLOUJ1Y2tldFBvbGljeSAtIEFjY2Vzc1NwZWMgd2l0aCBzZXQgb2YgY2FwYWJpbGl0aWVzJywgKCkgPT4ge1xuICAgIGNvbnN0IGxvY2Fsc3RhY2sgPSBuZXcgY2RrLlN0YWNrKGFwcCwgJ0s5QnVja2V0UG9saWN5TXVsdGlBY2Nlc3NDYXBhJyk7XG4gICAgY29uc3QgYnVja2V0ID0gbmV3IHMzLkJ1Y2tldChsb2NhbHN0YWNrLCAnVGVzdEJ1Y2tldFdpdGhNdWx0aUFjY2Vzc1NwZWMnLCB7fSk7XG5cbiAgICBjb25zdCBrOUJ1Y2tldFBvbGljeVByb3BzOiBLOUJ1Y2tldFBvbGljeVByb3BzID0ge1xuICAgICAgICBidWNrZXQ6IGJ1Y2tldCxcbiAgICAgICAgazlEZXNpcmVkQWNjZXNzOiBuZXcgQXJyYXk8QWNjZXNzU3BlYz4oXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBbXG4gICAgICAgICAgICAgICAgICAgIEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgICAgICBBY2Nlc3NDYXBhYmlsaXR5LlJlYWRDb25maWdcbiAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5pc3RlclJlc291cmNlQXJucyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBbXG4gICAgICAgICAgICAgICAgICAgIEFjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGEsXG4gICAgICAgICAgICAgICAgICAgIEFjY2Vzc0NhcGFiaWxpdHkuV3JpdGVEYXRhLFxuICAgICAgICAgICAgICAgICAgICBBY2Nlc3NDYXBhYmlsaXR5LkRlbGV0ZURhdGEsXG4gICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IHdyaXRlRGF0YUFybnMsXG4gICAgICAgICAgICB9LFxuICAgICAgICApXG4gICAgfTtcbiAgICBsZXQgYWRkVG9SZXNvdXJjZVBvbGljeVJlc3VsdHMgPSBrOS5zMy5ncmFudEFjY2Vzc1ZpYVJlc291cmNlUG9saWN5KGxvY2Fsc3RhY2ssIFwiUzNCdWNrZXRNdWx0aUFjY2Vzc1NwZWNcIiwgazlCdWNrZXRQb2xpY3lQcm9wcyk7XG4gICAgZXhwZWN0KGJ1Y2tldC5wb2xpY3kpLnRvQmVEZWZpbmVkKCk7XG5cbiAgICBjb25zb2xlLmxvZyhcImJ1Y2tldC5wb2xpY3k/LmRvY3VtZW50OiBcIiArIHN0cmluZ2lmeVBvbGljeShidWNrZXQucG9saWN5Py5kb2N1bWVudCkpO1xuICAgIGV4cGVjdChidWNrZXQucG9saWN5Py5kb2N1bWVudCkudG9CZURlZmluZWQoKTtcblxuICAgIGFzc2VydEs5U3RhdGVtZW50c0FkZGVkVG9TM1Jlc291cmNlUG9saWN5KGFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHRzKTtcblxuICAgIGV4cGVjdENESyhsb2NhbHN0YWNrKS50byhoYXZlUmVzb3VyY2UoXCJBV1M6OlMzOjpCdWNrZXRcIikpO1xuICAgIGV4cGVjdENESyhsb2NhbHN0YWNrKS50byhoYXZlUmVzb3VyY2UoXCJBV1M6OlMzOjpCdWNrZXRQb2xpY3lcIikpO1xuICAgIGV4cGVjdChTeW50aFV0aWxzLnRvQ2xvdWRGb3JtYXRpb24obG9jYWxzdGFjaykpLnRvTWF0Y2hTbmFwc2hvdCgpO1xufSk7XG5cbnRlc3QoJ2s5LnMzLmdyYW50QWNjZXNzVmlhUmVzb3VyY2VQb2xpY3kgbWVyZ2VzIHBlcm1pc3Npb25zIGZvciBhdXRvRGVsZXRlT2JqZWN0cycsICgpID0+IHtcbiAgICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soYXBwLCAnTWFuYWdlUGVybWlzc2lvbnNGb3JBdXRvRGVsZXRlT2JqZWN0cycpO1xuICAgIGNvbnN0IGJ1Y2tldCA9IG5ldyBzMy5CdWNrZXQoc3RhY2ssICdBdXRvRGVsZXRlQnVja2V0Jywge1xuICAgICAgICBhdXRvRGVsZXRlT2JqZWN0czogdHJ1ZSxcbiAgICAgICAgcmVtb3ZhbFBvbGljeTogUmVtb3ZhbFBvbGljeS5ERVNUUk9ZXG4gICAgfSk7XG5cbiAgICBsZXQgb3JpZ2luYWxCdWNrZXRQb2xpY3kgPSBidWNrZXQucG9saWN5O1xuICAgIGV4cGVjdChvcmlnaW5hbEJ1Y2tldFBvbGljeSkudG9CZVRydXRoeSgpO1xuICAgIGNvbnNvbGUubG9nKFwib3JpZ2luYWwgYnVja2V0UG9saWN5LmRvY3VtZW50OiBcIiArIHN0cmluZ2lmeVBvbGljeShidWNrZXQ/LnBvbGljeT8uZG9jdW1lbnQpKTtcblxuICAgIGNvbnN0IGs5QnVja2V0UG9saWN5UHJvcHM6IEs5QnVja2V0UG9saWN5UHJvcHMgPSB7XG4gICAgICAgIGJ1Y2tldDogYnVja2V0LFxuICAgICAgICBrOURlc2lyZWRBY2Nlc3M6IG5ldyBBcnJheTxBY2Nlc3NTcGVjPihcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuQWRtaW5pc3RlclJlc291cmNlLFxuICAgICAgICAgICAgICAgIGFsbG93UHJpbmNpcGFsQXJuczogYWRtaW5pc3RlclJlc291cmNlQXJucyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkRlbGV0ZURhdGEsXG4gICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBkZWxldGVEYXRhQXJucyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgIClcbiAgICB9O1xuICAgIGxldCBhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cyA9IGs5LnMzLmdyYW50QWNjZXNzVmlhUmVzb3VyY2VQb2xpY3koc3RhY2ssIFwiQXV0b0RlbGV0ZUJ1Y2tldFwiLCBrOUJ1Y2tldFBvbGljeVByb3BzKTtcblxuICAgIGV4cGVjdChidWNrZXQucG9saWN5KS50b1N0cmljdEVxdWFsKG9yaWdpbmFsQnVja2V0UG9saWN5KTtcbiAgICBcbiAgICBhc3NlcnRLOVN0YXRlbWVudHNBZGRlZFRvUzNSZXNvdXJjZVBvbGljeShhZGRUb1Jlc291cmNlUG9saWN5UmVzdWx0cyk7XG4gICAgXG4gICAgY29uc29sZS5sb2coXCJrOSBidWNrZXQgcG9saWN5OiBcIiArIHN0cmluZ2lmeVBvbGljeShidWNrZXQucG9saWN5Py5kb2N1bWVudCkpO1xuICAgIGV4cGVjdChTeW50aFV0aWxzLnRvQ2xvdWRGb3JtYXRpb24oc3RhY2spKS50b01hdGNoU25hcHNob3QoKTtcbn0pO1xuXG5kZXNjcmliZSgnSzlLZXlQb2xpY3knLCAoKSA9PiB7XG4gICAgY29uc3QgZGVzaXJlZEFjY2VzcyA9IG5ldyBBcnJheTxBY2Nlc3NTcGVjPihcbiAgICAgICAge1xuICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBbXG4gICAgICAgICAgICAgICAgQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2UsXG4gICAgICAgICAgICAgICAgQWNjZXNzQ2FwYWJpbGl0eS5SZWFkQ29uZmlnXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBhZG1pbmlzdGVyUmVzb3VyY2VBcm5zLFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuV3JpdGVEYXRhLFxuICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiB3cml0ZURhdGFBcm5zLFxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgICBhY2Nlc3NDYXBhYmlsaXRpZXM6IEFjY2Vzc0NhcGFiaWxpdHkuUmVhZERhdGEsXG4gICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IHJlYWREYXRhQXJucyxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgICAgYWNjZXNzQ2FwYWJpbGl0aWVzOiBBY2Nlc3NDYXBhYmlsaXR5LkRlbGV0ZURhdGEsXG4gICAgICAgICAgICBhbGxvd1ByaW5jaXBhbEFybnM6IGRlbGV0ZURhdGFBcm5zLFxuICAgICAgICB9LFxuICAgICk7XG4gICAgdGVzdCgnV2l0aG91dCBBbGxvdyByb290IHVzZXIgYW5kIElkZW50aXR5IHBvbGljaWVzJywgKCkgPT4ge1xuICAgICAgICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soYXBwLCAnV2l0aG91dFJvb3RBbmRJZGVudGl0eVBvbGljaWVzJyk7XG4gICAgICAgIGNvbnN0IGs5S2V5UG9saWN5UHJvcHM6IEs5S2V5UG9saWN5UHJvcHMgPSB7XG4gICAgICAgICAgICBrOURlc2lyZWRBY2Nlc3M6IGRlc2lyZWRBY2Nlc3NcbiAgICAgICAgfTtcblxuICAgICAgICBleHBlY3QoazlLZXlQb2xpY3lQcm9wcy50cnVzdEFjY291bnRJZGVudGl0aWVzKS50b0JlRmFsc3koKTtcbiAgICAgICAgY29uc3Qga2V5UG9saWN5ID0gazkua21zLm1ha2VLZXlQb2xpY3koazlLZXlQb2xpY3lQcm9wcyk7XG5cbiAgICAgICAgbGV0IHBvbGljeUpzb25TdHIgPSBzdHJpbmdpZnlQb2xpY3koa2V5UG9saWN5KTtcbiAgICAgICAgY29uc29sZS5sb2coYGtleVBvbGljeS5kb2N1bWVudCAodHJ1c3RBY2NvdW50SWRlbnRpdGllczogJHtrOUtleVBvbGljeVByb3BzLnRydXN0QWNjb3VudElkZW50aXRpZXN9KTogJHtwb2xpY3lKc29uU3RyfWApO1xuICAgICAgICBsZXQgcG9saWN5T2JqID0gSlNPTi5wYXJzZShwb2xpY3lKc29uU3RyKTtcblxuICAgICAgICBsZXQgYWN0dWFsUG9saWN5U3RhdGVtZW50cyA9IHBvbGljeU9ialsnU3RhdGVtZW50J107XG4gICAgICAgIGV4cGVjdChhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKS50b0JlRGVmaW5lZCgpO1xuXG4gICAgICAgIGxldCBkZW55RXZlcnlvbmVFbHNlU3RtdDogYW55O1xuICAgICAgICBsZXQgYWxsb3dSb290U3RtdDogYW55O1xuICAgICAgICBmb3IgKGxldCBzdG10IG9mIGFjdHVhbFBvbGljeVN0YXRlbWVudHMpIHtcbiAgICAgICAgICAgIGlmKFNJRF9ERU5ZX0VWRVJZT05FX0VMU0UgPT0gc3RtdC5TaWQpe1xuICAgICAgICAgICAgICAgIGRlbnlFdmVyeW9uZUVsc2VTdG10ID0gc3RtdDtcbiAgICAgICAgICAgIH0gZWxzZSBpZihTSURfQUxMT1dfUk9PVF9BTkRfSURFTlRJVFlfUE9MSUNJRVMgPT0gc3RtdC5TaWQpe1xuICAgICAgICAgICAgICAgIGFsbG93Um9vdFN0bXQgPSBzdG10O1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgZXhwZWN0KGRlbnlFdmVyeW9uZUVsc2VTdG10KS50b0JlRmFsc3koKTtcbiAgICAgICAgZXhwZWN0KGFsbG93Um9vdFN0bXQpLnRvQmVGYWxzeSgpO1xuXG4gICAgICAgIG5ldyBrbXMuS2V5KHN0YWNrLCAnVGVzdEtleU5vUm9vdCcsIHtwb2xpY3k6IGtleVBvbGljeX0pO1xuXG4gICAgICAgIGV4cGVjdENESyhzdGFjaykudG8oaGF2ZVJlc291cmNlKFwiQVdTOjpLTVM6OktleVwiKSk7XG4gICAgICAgIGV4cGVjdChTeW50aFV0aWxzLnRvQ2xvdWRGb3JtYXRpb24oc3RhY2spKS50b01hdGNoU25hcHNob3QoKTtcbiAgICB9KTtcbiAgICBcbiAgICB0ZXN0KCdBbGxvdyByb290IHVzZXIgYW5kIElkZW50aXR5IHBvbGljaWVzJywgKCkgPT4ge1xuICAgICAgICBjb25zdCBzdGFjayA9IG5ldyBjZGsuU3RhY2soYXBwLCAnV2l0aFJvb3RBbmRJZGVudGl0eVBvbGljaWVzJyk7XG4gICAgICAgIGNvbnN0IGs5S2V5UG9saWN5UHJvcHM6IEs5S2V5UG9saWN5UHJvcHMgPSB7XG4gICAgICAgICAgICBrOURlc2lyZWRBY2Nlc3M6IGRlc2lyZWRBY2Nlc3MsXG4gICAgICAgICAgICB0cnVzdEFjY291bnRJZGVudGl0aWVzOiB0cnVlXG4gICAgICAgIH07XG4gICAgICAgIFxuICAgICAgICBleHBlY3QoazlLZXlQb2xpY3lQcm9wcy50cnVzdEFjY291bnRJZGVudGl0aWVzKS50b0JlVHJ1dGh5KCk7XG4gICAgICAgIGNvbnN0IGtleVBvbGljeSA9IGs5Lmttcy5tYWtlS2V5UG9saWN5KGs5S2V5UG9saWN5UHJvcHMpO1xuXG4gICAgICAgIGxldCBwb2xpY3lKc29uU3RyID0gc3RyaW5naWZ5UG9saWN5KGtleVBvbGljeSk7XG4gICAgICAgIGNvbnNvbGUubG9nKGBrZXlQb2xpY3kuZG9jdW1lbnQgKHRydXN0QWNjb3VudElkZW50aXRpZXM6ICR7azlLZXlQb2xpY3lQcm9wcy50cnVzdEFjY291bnRJZGVudGl0aWVzfSk6ICR7cG9saWN5SnNvblN0cn1gKTtcbiAgICAgICAgbGV0IHBvbGljeU9iaiA9IEpTT04ucGFyc2UocG9saWN5SnNvblN0cik7XG5cbiAgICAgICAgbGV0IGFjdHVhbFBvbGljeVN0YXRlbWVudHMgPSBwb2xpY3lPYmpbJ1N0YXRlbWVudCddO1xuICAgICAgICBleHBlY3QoYWN0dWFsUG9saWN5U3RhdGVtZW50cykudG9CZURlZmluZWQoKTtcblxuICAgICAgICBsZXQgZGVueUV2ZXJ5b25lRWxzZVN0bXQ6IGFueTtcbiAgICAgICAgbGV0IGFsbG93Um9vdFN0bXQ6IGFueTtcbiAgICAgICAgZm9yIChsZXQgc3RtdCBvZiBhY3R1YWxQb2xpY3lTdGF0ZW1lbnRzKSB7XG4gICAgICAgICAgICBpZihTSURfREVOWV9FVkVSWU9ORV9FTFNFID09IHN0bXQuU2lkKXtcbiAgICAgICAgICAgICAgICBkZW55RXZlcnlvbmVFbHNlU3RtdCA9IHN0bXQ7XG4gICAgICAgICAgICB9IGVsc2UgaWYoU0lEX0FMTE9XX1JPT1RfQU5EX0lERU5USVRZX1BPTElDSUVTID09IHN0bXQuU2lkKXtcbiAgICAgICAgICAgICAgICBhbGxvd1Jvb3RTdG10ID0gc3RtdDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGV4cGVjdChkZW55RXZlcnlvbmVFbHNlU3RtdCkudG9CZVRydXRoeSgpO1xuICAgICAgICBleHBlY3QoYWxsb3dSb290U3RtdCkudG9CZVRydXRoeSgpO1xuXG5cbiAgICAgICAgbmV3IGttcy5LZXkoc3RhY2ssICdUZXN0S2V5QWxsb3dSb290Jywge3BvbGljeToga2V5UG9saWN5fSk7XG5cbiAgICAgICAgZXhwZWN0Q0RLKHN0YWNrKS50byhoYXZlUmVzb3VyY2UoXCJBV1M6OktNUzo6S2V5XCIpKTtcbiAgICAgICAgZXhwZWN0KFN5bnRoVXRpbHMudG9DbG91ZEZvcm1hdGlvbihzdGFjaykpLnRvTWF0Y2hTbmFwc2hvdCgpO1xuICAgIH0pO1xuXG4gICAgdGVzdCgnVW5tYW5hZ2VhYmxlIGtleSBwb2xpY3kgaXMgcmVqZWN0ZWQnLCAoKSA9PiB7XG5cbiAgICAgICAgY29uc3QgdW5tYW5hZ2VhYmxlQ2FwYWJpbGl0eUNvbWJvcyA9IFtcbiAgICAgICAgICBbXSxcbiAgICAgICAgICBbQWNjZXNzQ2FwYWJpbGl0eS5BZG1pbmlzdGVyUmVzb3VyY2VdLFxuICAgICAgICAgIFtBY2Nlc3NDYXBhYmlsaXR5LlJlYWRDb25maWddLFxuICAgICAgICAgIFtBY2Nlc3NDYXBhYmlsaXR5LkFkbWluaXN0ZXJSZXNvdXJjZSwgQWNjZXNzQ2FwYWJpbGl0eS5Xcml0ZURhdGFdXG4gICAgICAgIF07XG5cbiAgICAgICAgZm9yKGxldCB0cnVzdEFjY291bnRJZGVudGl0aWVzIG9mIFt0cnVlLCBmYWxzZV0pe1xuICAgICAgICAgICAgZm9yKGxldCB1bm1hbmFnZWFibGVBY2Nlc3NDYXBhYmlsaXRpZXMgb2YgdW5tYW5hZ2VhYmxlQ2FwYWJpbGl0eUNvbWJvcyl7XG4gICAgICAgICAgICAgICAgbGV0IGRlc2lyZWRBY2Nlc3MgPSBuZXcgQXJyYXk8QWNjZXNzU3BlYz4oXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIGFjY2Vzc0NhcGFiaWxpdGllczogdW5tYW5hZ2VhYmxlQWNjZXNzQ2FwYWJpbGl0aWVzLFxuICAgICAgICAgICAgICAgICAgICAgICAgYWxsb3dQcmluY2lwYWxBcm5zOiBhZG1pbmlzdGVyUmVzb3VyY2VBcm5zLFxuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgICBsZXQgazlLZXlQb2xpY3lQcm9wczogSzlLZXlQb2xpY3lQcm9wcyA9IHtcbiAgICAgICAgICAgICAgICAgICAgazlEZXNpcmVkQWNjZXNzOiBkZXNpcmVkQWNjZXNzLFxuICAgICAgICAgICAgICAgICAgICB0cnVzdEFjY291bnRJZGVudGl0aWVzOiB0cnVlXG4gICAgICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgICAgIGV4cGVjdCgoKSA9PiBrOS5rbXMubWFrZUtleVBvbGljeShrOUtleVBvbGljeVByb3BzKSlcbiAgICAgICAgICAgICAgICAgICAgLnRvVGhyb3coL0F0IGxlYXN0IG9uZSBwcmluY2lwYWwgbXVzdCBiZSBhYmxlIHRvIGFkbWluaXN0ZXIgYW5kIHJlYWQtY29uZmlnIGZvciBrZXlzLylcblxuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cbiAgICB9KTtcblxufSk7XG5cbmZ1bmN0aW9uIGFzc2VydENvbnRhaW5zU3RhdGVtZW50V2l0aElkKGV4cGVjdFN0bXRJZDpzdHJpbmcsIHN0YXRlbWVudHM6YW55KXtcbiAgICBsZXQgZm91bmRTdG10ID0gZmFsc2U7XG4gICAgY29uc29sZS5sb2coYGxvb2tpbmcgZm9yIHN0YXRlbWVudCBpZDogJHtleHBlY3RTdG10SWR9YClcbiAgICBmb3IgKGxldCBzdG10IG9mIHN0YXRlbWVudHMpIHtcbiAgICAgICAgaWYoZXhwZWN0U3RtdElkID09IHN0bXQuU2lkKXtcbiAgICAgICAgICBmb3VuZFN0bXQgPSB0cnVlO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgfVxuICAgIGV4cGVjdChmb3VuZFN0bXQpLnRvQmVUcnV0aHkoKTtcbn1cblxuZnVuY3Rpb24gYXNzZXJ0SzlTdGF0ZW1lbnRzQWRkZWRUb1MzUmVzb3VyY2VQb2xpY3koYWRkVG9SZXNvdXJjZVBvbGljeVJlc3VsdHM6IEFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHRbXSwgazlCdWNrZXRQb2xpY3lQcm9wcz86IEs5QnVja2V0UG9saWN5UHJvcHMpIHtcbiAgICBsZXQgbnVtRXhwZWN0ZWRTdGF0ZW1lbnRzID0gOTtcbiAgICBpZihrOUJ1Y2tldFBvbGljeVByb3BzICYmIGs5QnVja2V0UG9saWN5UHJvcHMucHVibGljUmVhZEFjY2Vzcyl7XG4gICAgICAgIG51bUV4cGVjdGVkU3RhdGVtZW50cyArPSAxO1xuICAgIH1cbiAgICBleHBlY3QoYWRkVG9SZXNvdXJjZVBvbGljeVJlc3VsdHMubGVuZ3RoKS50b0VxdWFsKG51bUV4cGVjdGVkU3RhdGVtZW50cyk7XG4gICAgZm9yIChsZXQgcmVzdWx0IG9mIGFkZFRvUmVzb3VyY2VQb2xpY3lSZXN1bHRzKSB7XG4gICAgICAgIGV4cGVjdChyZXN1bHQuc3RhdGVtZW50QWRkZWQpLnRvQmVUcnV0aHkoKTtcbiAgICB9XG59XG4iXX0=