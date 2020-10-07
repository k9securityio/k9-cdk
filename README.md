# k9 AWS CDK policy library #

k9 Security's `k9-cdk` helps you protect data by provisioning strong AWS security bucket with safe defaults and a 
least-privilege bucket policy built on the 
[k9 access capability model](https://k9security.io/docs/k9-access-capability-model/).

## Local Development and Testing

 * `npm run build`   compile typescript to js
 * `npm run watch`   watch for changes and compile
 * `npm run test`    perform the jest unit tests
 * `cdk deploy`      deploy this stack to your default AWS account/region
 * `cdk diff`        compare deployed stack with current state
 * `cdk synth`       emits the synthesized CloudFormation template
