import { AnyPrincipal, ArnPrincipal, Effect, PolicyStatement, PolicyStatementProps } from 'aws-cdk-lib/aws-iam';

export type ArnEqualsTest = 'ArnEquals'

export type ArnLikeTest = 'ArnLike';

export type ArnConditionTest =
    | ArnEqualsTest
    | ArnLikeTest;

export enum AccessCapability {
  AdministerResource = 'administer-resource',
  ReadConfig = 'read-config',
  ReadData = 'read-data',
  WriteData = 'write-data',
  DeleteData = 'delete-data',
}

export interface AccessSpec {
  accessCapabilities: Array<AccessCapability> | AccessCapability;
  allowPrincipalArns: Array<string>;
  test?: ArnConditionTest;
}

export class K9PolicyFactory {

  SUPPORTED_SERVICES = new Set<string>([
    'S3',
    'KMS',
  ]);
  _K9CapabilityMapJSON: Object = require('../resources/capability_summary.json');
  K9CapabilityMapByService: Map<string, Object> = new Map(Object.entries(this._K9CapabilityMapJSON));

  getActions(service: string, accessCapability: AccessCapability): Array<string> {
    if (!this.SUPPORTED_SERVICES.has(service) && this.K9CapabilityMapByService.has(service)) {
      throw Error(`unsupported service: ${service}`);
    }

    let serviceCapabilitiesObj: Object = this.K9CapabilityMapByService.get(service) || {};
    let serviceCapabilitiesMap = new Map<string, Array<string>>(Object.entries(serviceCapabilitiesObj));

    let accessCapabilityName = accessCapability.toString();
    if (serviceCapabilitiesMap &&
            serviceCapabilitiesMap.has(accessCapabilityName)) {
      return serviceCapabilitiesMap.get(accessCapabilityName) || Array<string>();
    } else {
      return new Array<string>();
    }
  }

  _mergeAccessSpecs(target: AccessSpec, addition: AccessSpec) {
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

  }

  mergeDesiredAccessSpecsByCapability(supportedCapabilities: Array<AccessCapability>,
    desiredAccess: Array<AccessSpec>): Map<AccessCapability, AccessSpec> {

    let accessSpecsByCapability: Map<AccessCapability, AccessSpec> = new Map<AccessCapability, AccessSpec>();
    // 1. populate accessSpecsByCapability with fresh AccessSpecs for each supported capability
    // 2. iterate through desiredAccess specs and merge data into what we'll use
    //    important: detect mismatched test types
    //     we can leave `test` unset in the default access specs
    //     and copy the value from the spec being merged if it is set
    //     throw Error on mismatch
    // 3. generate an Allow statement for each supported capability

    for (let supportedCapability of supportedCapabilities) {
      //generate a default access spec for each of the service's supported capabilities
      let effectiveAccessSpec: AccessSpec = {
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
    return accessSpecsByCapability;
  }

  makeAllowStatements(serviceName: string,
    supportedCapabilities: Array<AccessCapability>,
    desiredAccess: Array<AccessSpec>,
    resourceArns: Array<string>): Array<PolicyStatement> {
    let policyStatements = new Array<PolicyStatement>();
    let accessSpecsByCapability: Map<AccessCapability, AccessSpec> = this.mergeDesiredAccessSpecsByCapability(supportedCapabilities, desiredAccess);

    // ok, time to actually make Allow Statements from our AccessSpecs
    for (let supportedCapability of supportedCapabilities) {

      let accessSpec: AccessSpec = accessSpecsByCapability.get(supportedCapability) ||
                { //satisfy compiler; should never happen, because we populate at the beginning.
                  //generate a default access spec if none was provided
                  accessCapabilities: [supportedCapability],
                  allowPrincipalArns: new Array<string>(),
                  test: 'ArnEquals',
                }
            ;

      let arnConditionTest = accessSpec.test || 'ArnEquals';

      let statement = this.makeAllowStatement(`Allow Restricted ${supportedCapability}`,
        this.getActions(serviceName, supportedCapability),
        accessSpec.allowPrincipalArns,
        arnConditionTest,
        resourceArns);
      policyStatements.push(statement);
    }
    return policyStatements;
  }

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

  makeAllowStatement(sid: string,
    actions: Array<string>,
    principalArns: Array<string>,
    test: ArnConditionTest,
    resources: Array<string>): PolicyStatement {
    const policyStatementProps: PolicyStatementProps = {
      sid: sid,
      effect: Effect.ALLOW,
    };
    const statement = new PolicyStatement(policyStatementProps);
    statement.addActions(...actions);
    statement.addAnyPrincipal();
    statement.addResources(...resources);
    statement.addCondition(test, { 'aws:PrincipalArn': K9PolicyFactory.deduplicatePrincipals(principalArns) });
    return statement;
  }

  wasLikeUsed(accessSpecs: AccessSpec[]): boolean {
    for (let accessSpec of accessSpecs) {
      if ('ArnLike' == accessSpec.test) {
        return true;
      }
    }
    return false;
  }

  getAllowedPrincipalArns(accessSpecs: AccessSpec[]): Set<string> {
    let allowedPrincipalArns = new Set<string>();
    for (let accessSpec of accessSpecs) {
      accessSpec.allowPrincipalArns.forEach(function (value) {
        allowedPrincipalArns.add(value);
      });
    }
    return allowedPrincipalArns;
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

}

