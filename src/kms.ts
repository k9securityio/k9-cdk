import * as iam from 'aws-cdk-lib/aws-iam';
import {
  AccountRootPrincipal, AnyPrincipal,
  Conditions,
  Effect,
  PolicyDocument,
  PolicyStatement,
  ServicePrincipal,
} from 'aws-cdk-lib/aws-iam';
import {
  AccessCapability,
  canPrincipalsManageResources,
  getAccessCapabilityFromValue,
  IAccessSpec,
  IAWSServiceAccessGenerator,
  K9PolicyFactory,
} from './k9policy';

export interface K9KeyPolicyProps {
  readonly k9DesiredAccess: Array<IAccessSpec>;
  readonly trustAccountIdentities?: boolean;
  /**
   * An (optional) array of IAWSServiceAccessGenerator instances which will generate statements to allow access to the
   * key by an AWS service like CloudFront or Kinesis.
   *
   * @default undefined
   */
  readonly awsServiceAccessGenerators?: Array<IAWSServiceAccessGenerator>;
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
  AccessCapability.ADMINISTER_RESOURCE,
  AccessCapability.READ_CONFIG,
  AccessCapability.READ_DATA,
  AccessCapability.WRITE_DATA,
  AccessCapability.DELETE_DATA,
);

export const SID_ALLOW_ROOT_AND_IDENTITY_POLICIES = 'Allow Root User to Administer Key And Identity Policies';
export const SID_DENY_EVERYONE_ELSE = 'DenyEveryoneElse';

/**
 * Generate key policy statements to enable the CloudFront service to read encrypted S3 bucket object data (only)
 * from within a <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html#sse-kms">CloudFront OAC integration</a>.
 */
export class CloudFrontOACReadAccessGenerator implements IAWSServiceAccessGenerator {

  static readonly SID_ALLOW_CLOUDFRONT_SVC_READ_DATA = 'Allow CloudFront Service read-data';
  static readonly SID_ALLOW_CLOUDFRONT_IAM_ROLE_READ_DATA = 'Allow CloudFront IAM role read-data';

  readonly distributionArn: string;

  constructor(distributionArn: string) {
    this.distributionArn = distributionArn;
  }

  makeAllowStatements(): Array<PolicyStatement> {
    return [new PolicyStatement({
      sid: CloudFrontOACReadAccessGenerator.SID_ALLOW_CLOUDFRONT_SVC_READ_DATA,
      effect: Effect.ALLOW,
      principals: [new ServicePrincipal('cloudfront.amazonaws.com')],
      actions: ['kms:Decrypt'],
      resources: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceArn': this.distributionArn },
      },
    }),
    new PolicyStatement({
      sid: CloudFrontOACReadAccessGenerator.SID_ALLOW_CLOUDFRONT_IAM_ROLE_READ_DATA,
      effect: Effect.ALLOW,
      principals: [new AnyPrincipal()],
      actions: ['kms:Decrypt'],
      resources: ['*'],
      conditions: {
        // use ArnEquals condition instead of a plain Principal element in case
        // the CloudFront service recreates the role.
        // conditions bind against the principal ARN at runtime.
        // the principal element binds (once) to the principal's canonical userid at policy definition time.
        ArnEquals: {
          'aws:PrincipalArn': 'arn:aws:iam::856369053181:role/OriginAccessControlRole',
        },
      },
    })];
  }

  makeConditionsToExceptFromDenyEveryoneElse(): Conditions {
    // return a (TypeScript) Record of the form:
    //     {"Operator": { "keyInRequestContext": "value" } }
    return { StringNotEqualsIfExists: { 'aws:PrincipalServiceName': 'cloudfront.amazonaws.com' } };
  }
}


export function makeKeyPolicy(props: K9KeyPolicyProps): PolicyDocument {
  const policyFactory = new K9PolicyFactory();
  const policy = new iam.PolicyDocument();

  const resourceArns = ['*'];

  let accessSpecsByCapabilityRecs = policyFactory.mergeDesiredAccessSpecsByCapability(SUPPORTED_CAPABILITIES, props.k9DesiredAccess);
  let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

  for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
    accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
  }

  if (!canPrincipalsManageResources(accessSpecsByCapability)) {
    throw Error('At least one principal must be able to administer and read-config for keys' +
            ' so encrypted data remains accessible; found:\n' +
            `administer-resource: '${accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE)?.allowPrincipalArns}'\n` +
            `read-config: '${accessSpecsByCapability.get(AccessCapability.READ_CONFIG)?.allowPrincipalArns}'`,
    );
  }

  const allowStatements = policyFactory.makeAllowStatements('KMS',
    SUPPORTED_CAPABILITIES,
    Array.from(accessSpecsByCapability.values()),
    resourceArns);
  policy.addStatements(...allowStatements);

  if (props.awsServiceAccessGenerators) {
    for (let serviceAccessSpec of props.awsServiceAccessGenerators) {
      policy.addStatements(...serviceAccessSpec.makeAllowStatements());
    }
  }

  //console.log(`trustAccountIdentities: ${props.trustAccountIdentities}`);

  // Allow root user and control access via Identity policy by aligning to Key's behavior:
  if (props.trustAccountIdentities) {
    //console.log('Adding Allow root and DenyEveryoneElse statements');
    const denyEveryoneElseStatement = new PolicyStatement({
      sid: SID_DENY_EVERYONE_ELSE,
      effect: Effect.DENY,
      principals: policyFactory.makeDenyEveryoneElsePrincipals(),
      actions: ['kms:*'],
      resources: resourceArns,
    });
    denyEveryoneElseStatement.addCondition('Bool', {
      'aws:PrincipalIsAWSService': ['false'],
      'kms:GrantIsForAWSResource': ['false'],
    });
    const denyEveryoneElseTest = policyFactory.wasLikeUsed(props.k9DesiredAccess) ?
      'ArnNotLike' :
      'ArnNotEquals';
    const allAllowedPrincipalArns = policyFactory.getAllowedPrincipalArns(props.k9DesiredAccess);
    const accountRootPrincipal = new AccountRootPrincipal();
    denyEveryoneElseStatement.addCondition(denyEveryoneElseTest, {
      'aws:PrincipalArn': [
        // Place Root Principal arn in stable, prominent position;
        // will render as an object Fn::Join'ing Partition & AccountId
        accountRootPrincipal.arn,
        ...allAllowedPrincipalArns,
      ],
    });

    policy.addStatements(
      // add AllowRootUserToAdministerKey statement and enable access granted via Identity policies
      new PolicyStatement({
        sid: SID_ALLOW_ROOT_AND_IDENTITY_POLICIES,
        effect: Effect.ALLOW,
        principals: [accountRootPrincipal],
        actions: ['kms:*'],
        resources: resourceArns,
      })
      , denyEveryoneElseStatement,
    );
  } else {

    // Omit Allow Root & DenyEveryoneElse statement
    //
    // Instead, implement least privilege by relying on KMS' special behavior that
    // enables granting access solely via a KMS key policy, *irrespective of* Identity policy.
    //
    // See: https://docs.aws.amazon.com/kms/latest/developerguide/control-access-overview.html#managing-access
    // "To allow access to a KMS key, you must use the key policy,
    //  *either alone* or in combination with IAM policies or grants.
    //  IAM policies by themselves are not sufficient to allow access to a KMS key,
    //  though you can use them in combination with a key policy."
    //

    //console.log('Omitting Allow root and DenyEveryoneElse statements');
  }

  policy.validateForResourcePolicy();

  return policy;
}
