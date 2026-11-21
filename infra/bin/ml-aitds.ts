#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AuthStack } from '../lib/auth-stack';
import { ApiStack } from '../lib/api-stack';
import { StateStack } from '../lib/state-stack';
import { TelemetryStack } from '../lib/telemetry-stack';
import { StreamingStack } from '../lib/streaming-stack';

const app = new cdk.App();
cdk.Tags.of(app).add('Project', 'ML-AITDS');

const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const stateStack = new StateStack(app, 'MLAITDS-State', {
  env,
  description: 'DynamoDB: authority_state, abuse_budget, authority_velocity, request_log_index',
});

const telemetryStack = new TelemetryStack(app, 'MLAITDS-Telemetry', {
  env,
  description: 'CloudWatch API access logs + S3 audit via Firehose',
});

const authStack = new AuthStack(app, 'MLAITDS-Auth', {
  env,
  description: 'Cognito User Pool + app client for HTTP API JWT',
});

const streamingStack = new StreamingStack(app, 'MLAITDS-Streaming', {
  env,
  description: 'SQS + MSK Serverless + Kafka emitter for security event streaming',
});

new ApiStack(app, 'MLAITDS-Api', {
  env,
  description: 'HTTP API + Cognito JWT + Lambdas + access logging',
  userPool: authStack.userPool,
  userPoolClient: authStack.userPoolClient,
  authorityStateTable: stateStack.authorityStateTable,
  abuseBudgetTable: stateStack.abuseBudgetTable,
  authorityVelocityTable: stateStack.authorityVelocityTable,
  requestLogIndexTable: stateStack.requestLogIndexTable,
  apiAccessLogGroup: telemetryStack.apiAccessLogGroup,
  auditBucket: telemetryStack.auditBucket,
  securityEventsQueue: streamingStack.securityEventsQueue,
  sagemakerAnomalyEndpointName: app.node.tryGetContext('mlAnomalyEndpoint') as string | undefined,
});

// Future: DetectionStack (SageMaker/Bedrock), MSK/Kinesis consumers — subscribe to the same
// telemetry patterns (Firehose/S3 or a shared data stream) without changing ApiStack props.

app.synth();
