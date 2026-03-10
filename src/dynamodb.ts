import { AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import * as iam from 'aws-cdk-lib/aws-iam';
import {
  AccessCapability,
  canPrincipalsManageResources,
  getAccessCapabilityFromValue,
  IAccessSpec,
  K9PolicyFactory,
} from './k9policy';


export interface K9DynamoDBResourcePolicyProps {
  readonly k9DesiredAccess: Array<IAccessSpec>;
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
  AccessCapability.ADMINISTER_RESOURCE,
  AccessCapability.READ_CONFIG,
  AccessCapability.READ_DATA,
  AccessCapability.WRITE_DATA,
  AccessCapability.DELETE_DATA,
);

export const SID_DENY_EVERYONE_ELSE = 'DenyEveryoneElse';

/**
 * Generate a DynamoDB resource policy from the provided props that can be attached to DynamoDB
 * resources, particularly tables & indices.
 *
 * @param props specifying desired access
 * @return a PolicyDocument that can be attached to DynamoDB resources
 */
export function makeResourcePolicy(props: K9DynamoDBResourcePolicyProps): PolicyDocument {
  const policyFactory = new K9PolicyFactory();
  const policy = new iam.PolicyDocument();

  const resourceArns = ['*'];

  let accessSpecsByCapabilityRecs = policyFactory.mergeDesiredAccessSpecsByCapability(SUPPORTED_CAPABILITIES, props.k9DesiredAccess);
  let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

  for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
    accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
  }

  if (!canPrincipalsManageResources(accessSpecsByCapability)) {
    throw Error('At least one principal must be able to administer and read-config for DynamoDB resources' +
            ' so data data remains accessible; found:\n' +
            `administer-resource: '${accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE)?.allowPrincipalArns}'\n` +
            `read-config: '${accessSpecsByCapability.get(AccessCapability.READ_CONFIG)?.allowPrincipalArns}'`,
    );
  }

  const allowStatements = policyFactory.makeAllowStatements('DynamoDB',
    SUPPORTED_CAPABILITIES,
    Array.from(accessSpecsByCapability.values()),
    resourceArns,
    true);
  policy.addStatements(...allowStatements);

  const denyEveryoneElseStatement = new PolicyStatement({
    sid: SID_DENY_EVERYONE_ELSE,
    effect: Effect.DENY,
    principals: policyFactory.makeDenyEveryoneElsePrincipals(),
    actions: ['dynamodb:*'],
    resources: resourceArns,
  });
  denyEveryoneElseStatement.addCondition('Bool', {
    'aws:PrincipalIsAWSService': ['false'],
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
    denyEveryoneElseStatement,
  );

  const denyUntrustedOrgsStatement = policyFactory._makeDenyUntrustedOrgsStatement(
    'DynamoDB', SUPPORTED_CAPABILITIES, accessSpecsByCapability, resourceArns);
  if (denyUntrustedOrgsStatement) {
    policy.addStatements(denyUntrustedOrgsStatement);
  }

  policy.validateForResourcePolicy();

  return policy;
}
