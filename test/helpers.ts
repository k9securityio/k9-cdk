import { PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';

export function fail(message: string) {
  throw new Error(message);
}

export function stringifyStatement(policyStatement?: PolicyStatement) {
  if (policyStatement) {
    return JSON.stringify(policyStatement.toStatementJson(), null, 2);
  } else {
    return '<none>';
  }
}
export function stringifyPolicy(policyDocument?: PolicyDocument) {
  if (policyDocument) {
    return JSON.stringify(policyDocument.toJSON(), null, 2);
  } else {
    return '<none>';
  }
}