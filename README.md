# k9 AWS CDK policy library #

k9 Security's `k9-cdk` helps you protect data by provisioning strong AWS security bucket with safe defaults and a 
least-privilege bucket policy built on the 
[k9 access capability model](https://k9security.io/docs/k9-access-capability-model/).

## Local Development and Testing

The high level build commands for this project are driven by `make`:

* `make all` - build library, run tests, and deploy 
* `make build` - build the library 
* `make unit-test` - run unit tests for the library
* `make converge` - deploy the integration test resources
* `make destroy` - destroy the integration test resources

The low level build commands for this project are:

 * `npm run build`   compile typescript to js
 * `npm run watch`   watch for changes and compile
 * `npm run test`    perform the jest unit tests
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk synth`       emits the synthesized CloudFormation template
