import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigatewayv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as apigatewayv2_authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as apigatewayv2_integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as path from 'path';

export interface ApiStackProps extends cdk.StackProps {
  userPool: cognito.IUserPool;
  userPoolClient: cognito.IUserPoolClient;
  authorityStateTable: dynamodb.ITable;
  abuseBudgetTable: dynamodb.ITable;
  authorityVelocityTable: dynamodb.ITable;
  requestLogIndexTable: dynamodb.ITable;
  apiAccessLogGroup: logs.ILogGroup;
  /** Structured decision + risk records (Lambda → S3); joins API access logs by requestId. */
  auditBucket: s3.IBucket;
  /** Optional: enqueue full audit payloads for Kafka emitter (StreamingStack). */
  securityEventsQueue?: sqs.IQueue;
  /**
   * Optional SageMaker endpoint name. Body in/out JSON contract:
   * request `{ "features": number[] }`, response `{ "score": number }` or `{ "anomaly_score": number }` in [0,1].
   */
  sagemakerAnomalyEndpointName?: string;
}

/** HTTP API with Cognito JWT authorizer, Lambda routes, and access logs → TelemetryStack. */
export class ApiStack extends cdk.Stack {
  public readonly httpApi: apigatewayv2.HttpApi;

  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);

    const issuer = `https://cognito-idp.${this.region}.amazonaws.com/${props.userPool.userPoolId}`;

    const jwtAuthorizer = new apigatewayv2_authorizers.HttpJwtAuthorizer(
      'JwtAuthorizer',
      issuer,
      { jwtAudience: [props.userPoolClient.userPoolClientId] },
    );

    const apiHandler = new NodejsFunction(this, 'ApiHandler', {
      runtime: lambda.Runtime.NODEJS_20_X,
      entry: path.join(__dirname, '..', 'lambdas', 'api', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.seconds(25),
      environment: {
        AUTHORITY_STATE_TABLE: props.authorityStateTable.tableName,
        ABUSE_BUDGET_TABLE: props.abuseBudgetTable.tableName,
        AUTHORITY_VELOCITY_TABLE: props.authorityVelocityTable.tableName,
        REQUEST_LOG_INDEX_TABLE: props.requestLogIndexTable.tableName,
        AUDIT_BUCKET_NAME: props.auditBucket.bucketName,
        ...(props.securityEventsQueue
          ? { SECURITY_EVENTS_QUEUE_URL: props.securityEventsQueue.queueUrl }
          : {}),
        ...(props.sagemakerAnomalyEndpointName
          ? { SAGEMAKER_ANOMALY_ENDPOINT: props.sagemakerAnomalyEndpointName }
          : {}),
      },
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node20',
      },
    });

    props.authorityStateTable.grantReadWriteData(apiHandler);
    props.abuseBudgetTable.grantReadWriteData(apiHandler);
    props.authorityVelocityTable.grantReadWriteData(apiHandler);
    props.requestLogIndexTable.grantReadWriteData(apiHandler);
    props.auditBucket.grantPut(apiHandler, 'api-decisions/*');
    props.securityEventsQueue?.grantSendMessages(apiHandler);

    if (props.sagemakerAnomalyEndpointName) {
      apiHandler.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['sagemaker:InvokeEndpoint'],
          resources: [
            `arn:aws:sagemaker:${this.region}:${this.account}:endpoint/${props.sagemakerAnomalyEndpointName}`,
          ],
        }),
      );
    }

    this.httpApi = new apigatewayv2.HttpApi(this, 'HttpApi', {
      apiName: 'mlaitds-http-api',
      description: 'ML-AITDS API (extend with DetectionStack / streaming later)',
      createDefaultStage: false,
      defaultAuthorizer: jwtAuthorizer,
      corsPreflight: {
        allowHeaders: ['authorization', 'content-type'],
        allowMethods: [
          apigatewayv2.CorsHttpMethod.GET,
          apigatewayv2.CorsHttpMethod.POST,
          apigatewayv2.CorsHttpMethod.OPTIONS,
        ],
        allowOrigins: ['*'],
        exposeHeaders: [
          'x-mlaitds-risk-score',
          'x-mlaitds-decision',
          'x-mlaitds-authority-level',
        ],
        maxAge: cdk.Duration.days(1),
      },
    });

    const integration = new apigatewayv2_integrations.HttpLambdaIntegration(
      'HelloIntegration',
      apiHandler,
    );

    this.httpApi.addRoutes({
      path: '/hello',
      methods: [apigatewayv2.HttpMethod.GET],
      integration,
    });

    this.httpApi.addRoutes({
      path: '/feedback',
      methods: [apigatewayv2.HttpMethod.POST],
      integration,
    });

    // HTTP API access logs cannot read arbitrary Lambda response headers; mirror fields in S3
    // (api-decisions/…) and Lambda stdout (MLAITDS_AUDIT JSON). Correlate on requestId.
    const accessLogFormat = JSON.stringify({
      requestId: '$context.requestId',
      requestTime: '$context.requestTime',
      httpMethod: '$context.httpMethod',
      routeKey: '$context.routeKey',
      status: '$context.status',
      integrationStatus: '$context.integration.status',
      integrationLatency: '$context.integration.latency',
      responseLatency: '$context.responseLatency',
      responseLength: '$context.responseLength',
      errorMessage: '$context.error.message',
      authorizerError: '$context.authorizer.error',
      authorizerClaims: '$context.authorizer.claims',
      sourceIp: '$context.identity.sourceIp',
      mlaitdsAuditHint: 's3:api-decisions/;lambda:MLAITDS_AUDIT',
    });

    new apigatewayv2.HttpStage(this, 'DefaultStage', {
      httpApi: this.httpApi,
      stageName: '$default',
      autoDeploy: true,
      accessLogSettings: {
        destinationArn: props.apiAccessLogGroup.logGroupArn,
        format: accessLogFormat.replace(/\s+/g, ''),
      },
    });

    new cdk.CfnOutput(this, 'HttpApiUrl', {
      value: this.httpApi.apiEndpoint,
      description: 'Base URL for the HTTP API',
    });
    new cdk.CfnOutput(this, 'HelloUrl', {
      value: `${this.httpApi.apiEndpoint}/hello`,
    });
    new cdk.CfnOutput(this, 'FeedbackUrl', {
      value: `${this.httpApi.apiEndpoint}/feedback`,
    });
  }
}
