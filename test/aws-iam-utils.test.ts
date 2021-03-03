import {PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";
import {getAllowedPrincipalArns} from "../lib/aws-iam-utils";

test('getAllowedPrincipalArns should return empty when Policy has no statements', () => {
    expect(getAllowedPrincipalArns(new PolicyDocument())).toEqual(new Set<string>());
});

test('getAllowedPrincipalArns should return principal for Allow Statement with one Principal', () => {
    const expectPrincipal = "arn:aws:iam::123456789012:role/Some-CustomS3AutoDeleteObject-Role";
    const policyStatement = PolicyStatement.fromJson({
                "Effect": "Allow",
                "Principal": {
                    "AWS": expectPrincipal
                },
                "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*", "s3:DeleteObject*"],
                "Resource": [
                    "arn:aws:s3:::a-bucket",
                    "arn:aws:s3:::a-bucket/*"
                ]
            });
    const policyDocument = new PolicyDocument();
    policyDocument.addStatements(policyStatement);
    expect(getAllowedPrincipalArns(policyDocument)).toEqual(new Set<string>([expectPrincipal]));
});

test('getAllowedPrincipalArns should return principals for Allow Statement with multiple Principals', () => {
    const expectPrincipal = [
        "arn:aws:iam::123456789012:role/Some-CustomS3AutoDeleteObject-Role",
        "${Token[TOKEN.55]}"
        ];
    const policyStatement = PolicyStatement.fromJson({
                "Effect": "Allow",
                "Principal": {
                    "AWS": expectPrincipal
                },
                "Action": ["s3:GetObject*", "s3:GetBucket*", "s3:List*", "s3:DeleteObject*"],
                "Resource": [
                    "arn:aws:s3:::a-bucket",
                    "arn:aws:s3:::a-bucket/*"
                ]
            });
    const policyDocument = new PolicyDocument();
    policyDocument.addStatements(policyStatement);
    expect(getAllowedPrincipalArns(policyDocument)).toEqual(new Set<string>(expectPrincipal));
});

