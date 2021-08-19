import {PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";

export function stringifyStatement(policyStatement?: PolicyStatement) {
    if(policyStatement){
        return JSON.stringify(policyStatement.toStatementJson(), null, 2);
    } else {
        return "<none>"
    }
}
export function stringifyPolicy(policyDocument?: PolicyDocument) {
    if(policyDocument){
        return JSON.stringify(policyDocument.toJSON(), null, 2);
    } else {
        return "<none>"
    }
}