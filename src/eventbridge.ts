import { CfnEventBusPolicy, IEventBus } from 'aws-cdk-lib/aws-events';
import { AccountRootPrincipal, Effect, PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';
import {
  AccessCapability,
  canPrincipalsManageResources,
  getAccessCapabilityFromValue,
  IAccessSpec,
  K9PolicyFactory,
} from './k9policy';

export interface K9EventBridgeResourcePolicyProps {
  readonly eventBus: IEventBus;
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
 * Generate an EventBridge resource policy from the provided props that can be attached to an event bus.
 *
 * @param props specifying desired access
 * @return a PolicyDocument that can be attached to an EventBridge event bus
 */
export function makeResourcePolicy(props: K9EventBridgeResourcePolicyProps): PolicyDocument {
  const policyFactory = new K9PolicyFactory();
  const policy = new iam.PolicyDocument();
  const resourceArns = ['*'];

  let accessSpecsByCapabilityRecs = policyFactory.mergeDesiredAccessSpecsByCapability(SUPPORTED_CAPABILITIES, props.k9DesiredAccess);
  let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

  for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
    accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
  }

  if (!canPrincipalsManageResources(accessSpecsByCapability)) {
    throw Error('At least one principal must be able to administer and read-config' +
        ' for EventBridge resources so the event bus remains manageable;' +
        ' found:\n' + `administer-resource: '${accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE)?.allowPrincipalArns}'\n` +
        `read-config: '${accessSpecsByCapability.get(AccessCapability.READ_CONFIG)?.allowPrincipalArns}'`);
  }

  const allowStatements = policyFactory.makeAllowStatements('EventBridge',
    SUPPORTED_CAPABILITIES,
    Array.from(accessSpecsByCapability.values()),
    resourceArns,
    true);

  policy.addStatements(...allowStatements);

  // --- DenyEveryoneElse ---
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
      // Place Root Principal arn in stable, prominent position
      accountRootPrincipal.arn,
      ...allAllowedPrincipalArns,
    ],
  });

  policy.addStatements(denyEveryoneElseStatement);
  policy.validateForResourcePolicy();

  return policy;
}

/**
 * Grant access to an EventBridge event bus via resource policy using k9
 * IAccessSpec definitions.
 *
 * Because EventBridge resource policies are per-statement (each is a
 * separate AWS::Events::EventBusPolicy CloudFormation resource), this
 * function decomposes the generated PolicyDocument into individual
 * CfnEventBusPolicy resources.
 *
 * @param scope  CDK construct scope
 * @param id     Construct ID prefix
 * @param props  Event bus and desired access specification
 * @return array of CfnEventBusPolicy resources created
 */
export function grantAccessViaResourcePolicy(scope: Construct, id: string, props: K9EventBridgeResourcePolicyProps): CfnEventBusPolicy[] {
  const resourcePolicy = makeResourcePolicy(props);
  const policyJson = resourcePolicy.toJSON();
  const k9Statements = policyJson.Statement;
  const policies: CfnEventBusPolicy[] = [];

  for (let statement of k9Statements) {
    const sid = statement.Sid || `k9-${policies.length}`;
    const policy = new CfnEventBusPolicy(scope, `${id}-${sid}`, {
      eventBusName: props.eventBus.eventBusName,
      statementId: sid,
      statement: statement,
    });
    policies.push(policy);
  }

  return policies;
}
