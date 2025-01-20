import {
  AccountRootPrincipal,
  AddToResourcePolicyResult,
  Effect,
  PolicyDocument,
  PolicyStatement,
} from 'aws-cdk-lib/aws-iam';
import * as iam from 'aws-cdk-lib/aws-iam';
import { IQueue } from 'aws-cdk-lib/aws-sqs';
import {
  AccessCapability,
  canPrincipalsManageResources,
  getAccessCapabilityFromValue,
  IAccessSpec,
  K9PolicyFactory,
} from './k9policy';


export interface K9SQSResourcePolicyProps {
  readonly queue: IQueue;
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

function partitionArray<T>(arr: T[], maxLength: number): T[][] {
  const result: T[][] = [];
  for (let i = 0; i < arr.length; i += maxLength) {
    result.push(arr.slice(i, i + maxLength));
  }
  return result;
}

/**
 * Generate a SQS resource policy from the provided props that can be attached to a queue.
 *
 * @param props specifying desired access
 * @return a PolicyDocument that can be attached to an SQS queue
 */
export function makeResourcePolicy(props: K9SQSResourcePolicyProps): PolicyDocument {
  const policyFactory = new K9PolicyFactory();
  const policy = new iam.PolicyDocument();

  const resourceArns = ['*'];

  let accessSpecsByCapabilityRecs = policyFactory.mergeDesiredAccessSpecsByCapability(SUPPORTED_CAPABILITIES, props.k9DesiredAccess);
  let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

  for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
    accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
  }

  if (!canPrincipalsManageResources(accessSpecsByCapability)) {
    throw Error('At least one principal must be able to administer and read-config for SQS resources' +
            ' so data remains accessible; found:\n' +
            `administer-resource: '${accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE)?.allowPrincipalArns}'\n` +
            `read-config: '${accessSpecsByCapability.get(AccessCapability.READ_CONFIG)?.allowPrincipalArns}'`,
    );
  }

  const allowStatements = policyFactory.makeAllowStatements('SQS',
    SUPPORTED_CAPABILITIES,
    Array.from(accessSpecsByCapability.values()),
    resourceArns);

  const max_actions_in_statement = 7;
  for (let allowStatement of allowStatements) {
    //SQS resource policy has a limit of 7 actions per statement (Really).
    //But you can have as many statements as you want up to the queue policy size limit.
    //So, if an allowStatement has more than 7 actions (like the administer-resource statement does),
    //then create additional statements and spread the original statement's permissions across them
    if (allowStatement.actions.length > max_actions_in_statement) {
      const partitionedActions = partitionArray(allowStatement.actions, max_actions_in_statement);
      partitionedActions.forEach((actions, index) => {
        const newStatement = allowStatement.copy({
          sid: `${allowStatement.sid} ${index + 1}`,
          actions: actions,
        });
        policy.addStatements(newStatement);
      });
    } else {
      policy.addStatements(allowStatement);
    }
  }

  const denyEveryoneElseStatement = new PolicyStatement({
    sid: SID_DENY_EVERYONE_ELSE,
    effect: Effect.DENY,
    principals: policyFactory.makeDenyEveryoneElsePrincipals(),
    actions: ['sqs:*'],
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

  policy.validateForResourcePolicy();

  return policy;
}

/**
 * Grant access to a queue via resource policy using k9 IAccessSpec definitions. This function
 * is the preferred interface for granting access to a queue.
 *
 * The grant and make operations are split because SQS policies can only be managed via the
 * IQueue.addToResourcePolicy method but IQueue does not offer a way to read the policy.
 * So making the policy is done in a separate function so policy generation can be tested.
 *
 * @param props specifying the queue and desired access
 *
 * @return the results for adding each statement
 */
export function grantAccessViaResourcePolicy(props: K9SQSResourcePolicyProps):
AddToResourcePolicyResult[] {
  const resourcePolicy = makeResourcePolicy(props);

  resourcePolicy.validateForResourcePolicy();

  const policyJson = resourcePolicy.toJSON();
  const k9Statements = policyJson.Statement;
  const queue = props.queue;
  const addToResourcePolicyResults = new Array<AddToResourcePolicyResult>();

  for (let statement of k9Statements) {
    let addToResourcePolicyResult = queue.addToResourcePolicy(
      PolicyStatement.fromJson(statement),
    );
    addToResourcePolicyResults.push(addToResourcePolicyResult);
  }

  return addToResourcePolicyResults;
}
