import {Effect, PolicyDocument, PolicyStatement} from "@aws-cdk/aws-iam";

/**
 * Gets the unique set of Principal ARNs (or tokenized representation) that appear in the Principal element of
 * a Statement that Allows access from an existing PolicyDocument.  Parallels K9PolicyFactory#getAllowedPrincipalArns.
 *
 * Limitations:
 *  * does not examine the statement's condition element
 *  * does not do anything with NotPrincipal
 *
 * @param policyDocument to analyze
 * @return the set of allowed principal ARNs or tokens
 */
export function getAllowedPrincipalArns(policyDocument: PolicyDocument): Set<string> {
    const origStatements = new Array<PolicyStatement>();
    const origAllowedAWSPrincipals = new Set<string>();
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
                        origAllowedAWSPrincipals.add(awsPrincipals)
                    } else if (Array.isArray(awsPrincipals)) {
                        console.log(`origStatementJSON.Principal (array): ${awsPrincipals}`);
                        awsPrincipals.forEach(function (value) {
                            origAllowedAWSPrincipals.add(value);
                        });
                    } else {
                        console.log(`origStatementJSON.Principal (${typeof awsPrincipals}): ${JSON.stringify(awsPrincipals)}`);
                    }
                }
            }
        }
    }
    return origAllowedAWSPrincipals;
}