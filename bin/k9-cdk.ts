#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { K9CdkStack } from '../lib/k9-cdk-stack';

const app = new cdk.App();
new K9CdkStack(app, 'K9CdkStack');
