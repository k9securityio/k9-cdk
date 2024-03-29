/*
Copyright K9 Security, Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/
const { awscdk } = require('projen');

const project = new awscdk.AwsCdkConstructLibrary({
  name: 'k9-cdk',
  description: 'Provision strong AWS security policies easily using the AWS CDK.',
  packageName: '@k9securityio/k9-cdk', /* The "name" in package.json. */
  repositoryUrl: 'https://github.com/k9securityio/k9-cdk.git',
  keywords: ['IAM', 'Security', 'Utilities', 'Policy', 'IAM Policy', 'k9-cdk'],

  author: 'k9 Security',
  authorOrganization: true,
  authorAddress: 'hello@k9security.io',

  cdkVersion: '2.1.0',
  defaultReleaseBranch: 'v2-main',
  majorVersion: 2,

  testdir: 'test',

  npmDistTag: 'latest',

  // deps: [],                /* Runtime dependencies of this module. */
  /* devDeps contains Build dependencies for this module. */
  devDeps: [
    'yarn',
    'aws-cdk',
    '@aws-cdk/assert',
  ],

  docgen: false,
});

project.synth();
