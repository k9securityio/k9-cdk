import {
  AnyPrincipal,
  ArnPrincipal,
  Conditions,
  Effect,
  PolicyStatement,
  PolicyStatementProps,
} from 'aws-cdk-lib/aws-iam';

export type ArnEqualsTest = 'ArnEquals'

export type ArnLikeTest = 'ArnLike';

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;

export enum AccessCapability {
  ADMINISTER_RESOURCE = 'administer-resource',
  READ_CONFIG = 'read-config',
  READ_DATA = 'read-data',
  WRITE_DATA = 'write-data',
  DELETE_DATA = 'delete-data',
}

export function getAccessCapabilityFromValue(accessCapabilityStr: string): AccessCapability {
  //https://blog.logrocket.com/typescript-string-enums-guide/
  for (let key of Object.keys(AccessCapability)) {
    // @ts-ignore
    if (AccessCapability[key] == accessCapabilityStr) {
      // https://stackoverflow.com/questions/17380845/how-do-i-convert-a-string-to-enum-in-typescript
      let typedKey = <keyof typeof AccessCapability>key;
      return AccessCapability[typedKey];
    }
  }

  throw Error(`Could not get AccessCapability from value: ${accessCapabilityStr}`);
}

export interface IAccessSpec {
  accessCapabilities: Array<AccessCapability> | AccessCapability;
  allowPrincipalArns: Array<string>;
  test?: ArnConditionTest;
  /**
   * Optional list of AWS Organization IDs that restrict the principals specified
   * in `allowPrincipalArns`. When present, generated Allow statements will include
   * a `StringEquals` condition on `aws:PrincipalOrgID` and a DenyUntrustedOrgs statement will
   * be generated for the permissions that are restricted by org IDs.
   *
   * Org IDs restrict which principals are allowed — they do not replace
   * `allowPrincipalArns`. If you want to allow an entire org, add `*` to `allowPrincipalArns` and the org ID to
   * `restrictToPrincipalOrgIDs`.
   */
  restrictToPrincipalOrgIDs?: Array<string>;
}

/**
 * `IAWSServiceAccessGenerator` defines an interface that the k9 policy generators use to grant an AWS service
 * access to a protected resource.
 */
export interface IAWSServiceAccessGenerator {
  /**
   * Make an array of PolicyStatement objects that allow an AWS service, e.g. CloudFront, to access to the
   * protected AWS resource.
   */
  makeAllowStatements(): Array<PolicyStatement>;

  /**
   * Make a Conditions object that creates an exception for an AWS service in a protected resource's `DenyEveryoneElse`
   * statement.
   */
  makeConditionsToExceptFromDenyEveryoneElse(): Conditions;
}

/**
 * Check whether the provided access specs ensure that at least one principal can both read and administer configuration.
 * @param accessSpecsByCapability is a map of access specs keyed by access capability
 *
 * @return true when at least one principal that can administer and read configuration exists
 */
export function canPrincipalsManageResources(accessSpecsByCapability: Map<AccessCapability, IAccessSpec>) {
  let adminSpec = accessSpecsByCapability.get(AccessCapability.ADMINISTER_RESOURCE);
  let readConfigSpec = accessSpecsByCapability.get(AccessCapability.READ_CONFIG);

  if ((adminSpec?.allowPrincipalArns && adminSpec.allowPrincipalArns.length > 0)
        && (readConfigSpec?.allowPrincipalArns && readConfigSpec.allowPrincipalArns.length > 0)) {
    const adminPrincipals = new Set<string>(adminSpec.allowPrincipalArns);
    const readConfigPrincipals = new Set<string>(readConfigSpec.allowPrincipalArns);
    const intersection = new Set(
      [...adminPrincipals].filter(x => readConfigPrincipals.has(x)));
    return intersection.size > 0;
  }
  return false;
}


/**
 * Check if any access spec contains a wildcard principal ("*").
 */
export function hasWildcardPrincipal(accessSpecs: Array<IAccessSpec>): boolean {
  for (let spec of accessSpecs) {
    if (spec.allowPrincipalArns.includes('*')) {
      return true;
    }
  }
  return false;
}

/**
 * Validate that access specs have valid principal ARN + org constraint combinations.
 * Throws an error for invalid combinations:
 * - Empty allowPrincipalArns
 * - Wildcard allowPrincipalArns without restrictToPrincipalOrgIDs (public access)
 */
export function validateAccessSpecs(accessSpecs: Array<IAccessSpec>): void {
  for (let spec of accessSpecs) {
    if (!spec.allowPrincipalArns || spec.allowPrincipalArns.length === 0) {
      throw new Error(
        'allowPrincipalArns must not be empty; every resource policy statement requires a Principal element.',
      );
    }
    if (spec.allowPrincipalArns.includes('*') &&
        (!spec.restrictToPrincipalOrgIDs || spec.restrictToPrincipalOrgIDs.length === 0)) {
      throw new Error(
        'k9-cdk will not generate a resource policy that allows fully public access.' +
        ' Wildcard principal ("*") requires restrictToPrincipalOrgIDs to scope access.' +
        ' Consider specifying account principal ARNs or constraining to specific PrincipalOrgIDs.',
      );
    }
  }
}

/**
 * Converts a string to PascalCase, which is useful for e.g. policy types that don't
 * do not support spaces or hyphens in statement ids.
 *
 * @param input
 */
export function toPascalCase(input: string): string {
  // Remove placeholders like ${something} and trim whitespace
  const cleanedInput = input.replace(/\$\{.*?\}/g, '').trim();

  // Split the input into words based on spaces, hyphens, underscores, or other delimiters
  const words = cleanedInput.split(/[\s_\-]+/);

  // Convert each word to PascalCase
  return words
    .map(
      word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase(), // Capitalize the first letter, lower the rest
    )
    .join('');
}

export const SID_DENY_UNTRUSTED_ORGS = 'DenyUntrustedOrgs';

export class K9PolicyFactory {

  /**
   * Deduplicate an array of principals while preserving original order of principals.
   * Note that principals may contain either strings or objects, so naive array sorting
   * produces unstable results.
   *
   * @param principals
   */
  static deduplicatePrincipals(principals: Array<string|object>): Array<string|object> {
    const observedPrincipals = new Set<string|object>();
    const uniquePrincipals = new Array<string|object>();
    for (let principal of principals) {
      if (!observedPrincipals.has(principal)) {
        uniquePrincipals.push(principal);
        observedPrincipals.add(principal);
      }
    }
    return uniquePrincipals;
  }

  /** @internal */
  _SUPPORTED_SERVICES = new Set<string>([
    'S3',
    'KMS',
    'DynamoDB',
    'SQS',
    'EventBridge',
  ]);

  /** @internal */
  _K9CapabilityMapJSON: Object = require('../resources/capability_summary.json'); // eslint-disable-line @typescript-eslint/no-require-imports
  /** @internal */
  _K9CapabilityMapByService: Map<string, Object> = new Map(Object.entries(this._K9CapabilityMapJSON));

  getActions(service: string, accessCapability: AccessCapability): Array<string> {
    if (!this._SUPPORTED_SERVICES.has(service) && this._K9CapabilityMapByService.has(service)) {
      throw Error(`unsupported service: ${service}`);
    }

    let serviceCapabilitiesObj: Object = this._K9CapabilityMapByService.get(service) || {};
    let serviceCapabilitiesMap = new Map<string, Array<string>>(Object.entries(serviceCapabilitiesObj));

    let accessCapabilityName = accessCapability.toString();
    if (serviceCapabilitiesMap &&
            serviceCapabilitiesMap.has(accessCapabilityName)) {
      return serviceCapabilitiesMap.get(accessCapabilityName) || Array<string>();
    } else {
      return new Array<string>();
    }
  }

  /** @internal */
  _mergeAccessSpecs(target: IAccessSpec, addition: IAccessSpec) {
    target.allowPrincipalArns.push(...addition.allowPrincipalArns);
    if (target.test) {
      //ok, user has specified a test at some point; ensure this desiredAccessSpec.test matches
      if (target.test != addition.test) {
        let msg = 'Cannot merge AccessSpecs; test attributes do not match:' +
                    `\n${JSON.stringify(target)}\n${JSON.stringify(addition)}`;
        throw Error(msg);
      }
    } else {
      //first explicit test preference wins
      if (addition.test) {
        target.test = addition.test;
      }
    }

    // Merge restrictToPrincipalOrgIDs
    if (addition.restrictToPrincipalOrgIDs && addition.restrictToPrincipalOrgIDs.length > 0) {
      if (!target.restrictToPrincipalOrgIDs) {
        target.restrictToPrincipalOrgIDs = [];
      }
      target.restrictToPrincipalOrgIDs.push(...addition.restrictToPrincipalOrgIDs);
    }

  }

  mergeDesiredAccessSpecsByCapability(supportedCapabilities: Array<AccessCapability>,
    desiredAccess: Array<IAccessSpec>): Record<string, IAccessSpec> {

    let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map<AccessCapability, IAccessSpec>();
    // 1. populate accessSpecsByCapability with fresh AccessSpecs for each supported capability
    // 2. iterate through desiredAccess specs and merge data into what we'll use
    //    important: detect mismatched test types
    //     we can leave `test` unset in the default access specs
    //     and copy the value from the spec being merged if it is set
    //     throw Error on mismatch
    // 3. generate an Allow statement for each supported capability

    for (let supportedCapability of supportedCapabilities) {
      //generate a default access spec for each of the service's supported capabilities
      let effectiveAccessSpec: IAccessSpec = {
        accessCapabilities: supportedCapability,
        allowPrincipalArns: new Array<string>(),
        // leave 'test' property unset; will populate from user-provided data
      };
      accessSpecsByCapability.set(supportedCapability, effectiveAccessSpec);

      //now... merge in the user's desired access for this capability
      for (let desiredAccessSpec of desiredAccess) {
        if (desiredAccessSpec.accessCapabilities instanceof Array) {
          for (let desiredCapability of desiredAccessSpec.accessCapabilities) {
            if (supportedCapability == desiredCapability) {
              this._mergeAccessSpecs(effectiveAccessSpec, desiredAccessSpec);
            }
          }
        } else if (typeof desiredAccessSpec.accessCapabilities == 'string') {
          if (supportedCapability == desiredAccessSpec.accessCapabilities) {
            this._mergeAccessSpecs(effectiveAccessSpec, desiredAccessSpec);
          }
        } else {
          throw Error(`Unhandled type of accessCapabilities for ${desiredAccessSpec.accessCapabilities}`);
        }
      }
    }

    const records: Record<string, IAccessSpec> = {};
    accessSpecsByCapability.forEach(function (value, key) {
      records[key] = value;
    });
    return records;
  }

  makeAllowStatements(serviceName: string,
    supportedCapabilities: Array<AccessCapability>,
    desiredAccess: Array<IAccessSpec>,
    resourceArns: Array<string>,
    usePascalCase: boolean = false): Array<PolicyStatement> {
    let policyStatements = new Array<PolicyStatement>();
    let accessSpecsByCapabilityRecs = this.mergeDesiredAccessSpecsByCapability(supportedCapabilities, desiredAccess);
    let accessSpecsByCapability: Map<AccessCapability, IAccessSpec> = new Map();

    for (let [capabilityStr, accessSpec] of Object.entries(accessSpecsByCapabilityRecs)) {
      accessSpecsByCapability.set(getAccessCapabilityFromValue(capabilityStr), accessSpec);
    }

    // ok, time to actually make Allow Statements from our AccessSpecs
    for (let supportedCapability of supportedCapabilities) {

      let accessSpec: IAccessSpec = accessSpecsByCapability.get(supportedCapability) ||
                { //satisfy compiler; should never happen, because we populate at the beginning.
                  //generate a default access spec if none was provided
                  accessCapabilities: [supportedCapability],
                  allowPrincipalArns: new Array<string>(),
                  test: 'ArnEquals',
                }
            ;

      let arnConditionTest = accessSpec.test || 'ArnEquals';

      let sid = `Allow Restricted ${supportedCapability}`;
      if (usePascalCase) {
        sid = toPascalCase(sid);
      }

      let statement = this.makeAllowStatement(sid,
        this.getActions(serviceName, supportedCapability),
        accessSpec.allowPrincipalArns,
        arnConditionTest,
        resourceArns,
        accessSpec.restrictToPrincipalOrgIDs);
      policyStatements.push(statement);
    }
    return policyStatements;
  }

  makeAllowStatement(sid: string,
    actions: Array<string>,
    principalArns: Array<string>,
    test: ArnConditionTest,
    resources: Array<string>,
    restrictToPrincipalOrgIDs?: Array<string>): PolicyStatement {
    const policyStatementProps: PolicyStatementProps = {
      sid: sid,
      effect: Effect.ALLOW,
    };
    const statement = new PolicyStatement(policyStatementProps);
    statement.addActions(...actions);
    statement.addAnyPrincipal();
    statement.addResources(...resources);

    const isWildcardPrincipal = principalArns.includes('*');
    const hasOrgConstraint = restrictToPrincipalOrgIDs && restrictToPrincipalOrgIDs.length > 0;

    if (isWildcardPrincipal && hasOrgConstraint) {
      // Code Path B: wildcard + org constraint
      // Use Principal: "*" (already added via addAnyPrincipal) + aws:PrincipalOrgID condition
      // Do NOT add aws:PrincipalArn condition
      statement.addCondition('StringEquals', { 'aws:PrincipalOrgID': restrictToPrincipalOrgIDs });
    } else {
      // Code Path A: specific principal ARNs (existing behavior)
      statement.addCondition(test, { 'aws:PrincipalArn': K9PolicyFactory.deduplicatePrincipals(principalArns) });
      if (hasOrgConstraint) {
        // Specific ARNs + org constraint: both conditions must be true
        statement.addCondition('StringEquals', { 'aws:PrincipalOrgID': restrictToPrincipalOrgIDs });
      }
    }

    return statement;
  }

  wasLikeUsed(accessSpecs: IAccessSpec[]): boolean {
    for (let accessSpec of accessSpecs) {
      if ('ArnLike' == accessSpec.test) {
        return true;
      }
    }
    return false;
  }

  getAllowedPrincipalArns(accessSpecs: IAccessSpec[]): Array<string> {
    let allowedPrincipalArns = new Set<string>();
    for (let accessSpec of accessSpecs) {
      accessSpec.allowPrincipalArns.forEach(function (value) {
        allowedPrincipalArns.add(value);
      });
    }
    return Array.from(allowedPrincipalArns);
  }

  /**
     * k9 wants to deny all AWS accounts and IAM principals not explicitly allowed; this *should*
     * be straightforward, but it isn't because of the way aws-cdk merges and manipulates Principals.
     * @return list of principals for a DenyEveryoneElse statement
     */
  makeDenyEveryoneElsePrincipals(): ArnPrincipal[] {
    /**
         * We should be able to provide AnyPrincipal once (of course), but AWS CDK converts:
         * "Principal": {
         *   "AWS": "*"    // identifies all AWS accounts and IAM.
         * }
         * to:
         * "Principal": "*"  // identifies all principals including AWS Service principals
         *
         * That's a greater scope than we want.
         *
         * So provide AnyPrincipal twice, so aws-cdk maintains the array form.
         *
         * AWS rewrites the AWS member of the policy on save so
         * only the unique set of principals are included
         * So after these machinations, we end up with what we want.
         */
    return [new AnyPrincipal(), new AnyPrincipal()];
  }

  /**
   * Create a DenyUntrustedOrgs statement that explicitly denies principals from
   * untrusted orgs for org-restricted actions. This provides defense-in-depth
   * beyond the implicit deny from org-constrained Allow statements.
   *
   * The StringNotEquals condition on aws:PrincipalOrgID is inherently safe for
   * AWS service principals because the key is absent from their request context,
   * so the condition is not satisfied and the Deny does not apply.
   *
   * @return a PolicyStatement with Effect Deny, or undefined if no access specs have org restrictions
   * @internal
   */
  _makeDenyUntrustedOrgsStatement(
    serviceName: string,
    supportedCapabilities: Array<AccessCapability>,
    accessSpecsByCapability: Map<AccessCapability, IAccessSpec>,
    resourceArns: Array<string>,
  ): PolicyStatement | undefined {
    const allActions = new Set<string>();
    const allOrgIDs = new Set<string>();

    for (let capability of supportedCapabilities) {
      const accessSpec = accessSpecsByCapability.get(capability);
      if (accessSpec?.restrictToPrincipalOrgIDs && accessSpec.restrictToPrincipalOrgIDs.length > 0) {
        const actions = this.getActions(serviceName, capability);
        for (let action of actions) {
          allActions.add(action);
        }
        for (let orgID of accessSpec.restrictToPrincipalOrgIDs) {
          allOrgIDs.add(orgID);
        }
      }
    }

    if (allActions.size === 0) {
      return undefined;
    }

    const statement = new PolicyStatement({
      sid: SID_DENY_UNTRUSTED_ORGS,
      effect: Effect.DENY,
      principals: this.makeDenyEveryoneElsePrincipals(),
      actions: Array.from(allActions),
      resources: resourceArns,
    });
    statement.addCondition('Bool', {
      'aws:PrincipalIsAWSService': ['false'],
    });
    statement.addCondition('StringNotEquals', {
      'aws:PrincipalOrgID': Array.from(allOrgIDs),
    });

    return statement;
  }

}
