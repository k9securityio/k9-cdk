import {
  AccountRootPrincipal,
  AddToResourcePolicyResult,
  Effect,
  PolicyDocument,
  PolicyStatement,
} from 'aws-cdk-lib/aws-iam';
import * as iam from 'aws-cdk-lib/aws-iam';
import { EventBus } from 'aws-cdk-lib/aws-events';
import {
  AccessCapability,
  canPrincipalsManageResources,
  getAccessCapabilityFromValue,
  hasWildcardPrincipal,
  IAccessSpec,
  K9PolicyFactory,
  validateAccessSpecs,
} from './k9policy';


export interface K9EventBusResourcePolicyProps {
  readonly bus: EventBus;
  readonly k9DesiredAccess: Array<IAccessSpec>;
}

let SUPPORTED_CAPABILITIES = new Array<AccessCapability>(
  AccessCapability.ADMINISTER_RESOURCE,
  AccessCapability.READ_CONFIG,
  AccessCapability.WRITE_DATA,
);

export const SID_DENY_EVERYONE_ELSE = 'DenyEveryoneElse';

/**
 * Generate an EventBridge Bus resource policy from the provided props.
 *
 * @param props specifying desired access
 * @return a PolicyDocument that can be attached to an EventBridge event bus
 */
export function makeResourcePolicy(props: K9EventBusResourcePolicyProps): PolicyDocument {
  const policyFactory = new K9PolicyFactory();
  const policy = new iam.PolicyDocument();

  const resourceArns = ['*'];

  validateAccessSpecs(props.k9DesiredAccess);

  let accessSpecsByCapabilityRecs = policyFactory.mergeDesiredAccessSpecsByCapability(SUPPORTED_CAPABILITIES, props.k9DesiredAccess);
  let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

  for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
    accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
  }

  if (!canPrincipalsManageResources(accessSpecsByCapability)) {
    throw Error('At least one principal must be able to administer and read-config for EventBridge resources' +
            ' so the bus remains accessible; found:\n' +
            `administer-resource: '${accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE)?.allowPrincipalArns}'\n` +
            `read-config: '${accessSpecsByCapability.get(AccessCapability.READ_CONFIG)?.allowPrincipalArns}'`,
    );
  }

  const allowStatements = policyFactory.makeAllowStatements('EventBridge',
    SUPPORTED_CAPABILITIES,
    Array.from(accessSpecsByCapability.values()),
    resourceArns,
    true);
  policy.addStatements(...allowStatements);

  // DenyEveryoneElse — conditional on access pattern:
  // When wildcard + org constraint is used, skip DenyEveryoneElse because
  // putting "*" in the deny exception would exempt everyone.
  // The org constraint on the Allow side already limits access.
  if (!hasWildcardPrincipal(props.k9DesiredAccess)) {
    const denyEveryoneElseStatement = new PolicyStatement({
      sid: SID_DENY_EVERYONE_ELSE,
      effect: Effect.DENY,
      principals: policyFactory.makeDenyEveryoneElsePrincipals(),
      actions: ['events:*'],
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

    policy.addStatements(denyEveryoneElseStatement);
  }

  const denyUntrustedOrgsStatement = policyFactory._makeDenyUntrustedOrgsStatement(
    'EventBridge', SUPPORTED_CAPABILITIES, accessSpecsByCapability, resourceArns);
  if (denyUntrustedOrgsStatement) {
    policy.addStatements(denyUntrustedOrgsStatement);
  }

  policy.validateForResourcePolicy();

  return policy;
}

/**
 * Grant access to an event bus via resource policy using k9 IAccessSpec definitions.
 *
 * @param props specifying the event bus and desired access
 *
 * @return the results for adding each statement
 */
export function grantAccessViaResourcePolicy(props: K9EventBusResourcePolicyProps):
AddToResourcePolicyResult[] {
  const resourcePolicy = makeResourcePolicy(props);

  resourcePolicy.validateForResourcePolicy();

  const policyJson = resourcePolicy.toJSON();
  const k9Statements = policyJson.Statement;
  const bus = props.bus;
  const addToResourcePolicyResults = new Array<AddToResourcePolicyResult>();

  for (let statement of k9Statements) {
    let addToResourcePolicyResult = bus.addToResourcePolicy(
      PolicyStatement.fromJson(statement),
    );
    addToResourcePolicyResults.push(addToResourcePolicyResult);
  }

  return addToResourcePolicyResults;
}
