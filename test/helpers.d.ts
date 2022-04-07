import { PolicyDocument, PolicyStatement } from "@aws-cdk/aws-iam";
export declare function stringifyStatement(policyStatement?: PolicyStatement): string;
export declare function stringifyPolicy(policyDocument?: PolicyDocument): string;
