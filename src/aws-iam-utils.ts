import { Effect, PolicyDocument, PolicyStatement } from 'aws-cdk-lib/aws-iam';

/**
 * Gets the unique set of AWS Principal ARNs (or tokenized representation) that appear in the Principal element of
 * a Statement that Allows access from an existing PolicyDocument.  Parallels K9PolicyFactory#getAllowedPrincipalArns.
 *
 * Notes & Limitations:
 *  * only examines 'AWS' principal types, so no e.g. Service principals
 *  * only collects Principals from statements without a Condition element
 *  * does not do anything with NotPrincipal
 *
 * @param policyDocument to analyze
 * @return the set of allowed principal ARNs or tokens
 */
export function getAllowedPrincipalArns(policyDocument: PolicyDocument): Set<string> {
  const allowedAWSPrincipals = new Set<string>();
  if (policyDocument.statementCount > 0) {
    const policyJSON: any = policyDocument.toJSON();
    for (let statementJson of policyJSON.Statement) {
      let statement = PolicyStatement.fromJson(statementJson);
      if (statement.effect == Effect.ALLOW
                && statement.hasPrincipal) {
        if (statementJson?.Principal?.AWS
                    // Skip Statements with conditions because they're too complex
                    // to analyze right now.  Skipping seems like the conservative approach.
                    && undefined === statementJson.Condition
        ) {
          let awsPrincipals = statementJson.Principal.AWS;
          if (typeof awsPrincipals == 'string') {
            allowedAWSPrincipals.add(awsPrincipals);
          } else if (Array.isArray(awsPrincipals)) {
            awsPrincipals.forEach(function (value) {
              allowedAWSPrincipals.add(value);
            });
          } else {
            throw new Error(`Found unexpected and unhandled principal type: (${typeof awsPrincipals}): ${JSON.stringify(awsPrincipals)}`);
          }
        }
      }
    }
  }
  return allowedAWSPrincipals;
}