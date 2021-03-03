import {Effect, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";

/**
 * Gets all of the Principal ARNs (or tokenized representation) that appear in the Principal element of
 * a Statement that Allows access.
 *
 * Limitations:
 *  * does not examine the statement's condition element
 *  * does not do anything with NotPrincipal
 *
 * @param policyDocument to analyze
 * @return an array of principals or tokens
 */
export function getAllowedPrincipalArns(policyDocument: PolicyDocument): Array<string> {
    const origStatements = new Array<PolicyStatement>();
    const origAllowedAWSPrincipals = new Array<string>();
    if (policyDocument.statementCount > 0) {
        const origPolicyJSON: any = policyDocument.toJSON();
        for (let statementJson of origPolicyJSON.Statement) {
            let origStatement = PolicyStatement.fromJson(statementJson);
            origStatements.push(origStatement);
            if (origStatement.effect == Effect.ALLOW &&
                origStatement.hasPrincipal) {
                let origStatementJSON = origStatement.toStatementJson();
                console.log(`origStatementJSON: ${JSON.stringify(origStatementJSON)}`);
                if (origStatementJSON?.Principal?.AWS) {
                    let awsPrincipals = origStatementJSON.Principal.AWS;
                    if (typeof awsPrincipals == 'string') {
                        console.log(`origStatementJSON.Principal (str): ${awsPrincipals}`);
                        origAllowedAWSPrincipals.push(awsPrincipals)
                    } else if (Array.isArray(awsPrincipals)) {
                        console.log(`origStatementJSON.Principal (array): ${awsPrincipals}`);
                        origAllowedAWSPrincipals.push(...awsPrincipals)
                    } else {
                        console.log(`origStatementJSON.Principal (${typeof awsPrincipals}): ${JSON.stringify(awsPrincipals)}`);
                    }
                }
            }
        }
    }
    return origAllowedAWSPrincipals;
}