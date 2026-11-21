import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as logs_destinations from 'aws-cdk-lib/aws-logs-destinations';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as firehose from 'aws-cdk-lib/aws-kinesisfirehose';

export interface TelemetryStackProps extends cdk.StackProps {}

/**
 * API access logs (CloudWatch) + near-real-time archival to S3 via Firehose.
 * Later: add MSK subscription, OpenSearch, or cross-account sinks without changing ApiStack contract.
 */
export class TelemetryStack extends cdk.Stack {
  /** Log group API Gateway HTTP API writes access logs to (passed to ApiStack). */
  public readonly apiAccessLogGroup: logs.LogGroup;
  public readonly auditBucket: s3.Bucket;

  constructor(scope: Construct, id: string, props?: TelemetryStackProps) {
    super(scope, id, props);

    this.auditBucket = new s3.Bucket(this, 'AuditBucket', {
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    const deliveryStream = new firehose.DeliveryStream(this, 'AuditFirehose', {
      deliveryStreamName: 'mlaitds-api-access-audit',
      destination: new firehose.S3Bucket(this.auditBucket, {
        bufferingInterval: cdk.Duration.minutes(1),
        bufferingSize: cdk.Size.mebibytes(5),
      }),
    });

    this.apiAccessLogGroup = new logs.LogGroup(this, 'ApiAccessLogs', {
      logGroupName: '/mlaitds/http-api/access',
      retention: logs.RetentionDays.ONE_MONTH,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Allow API Gateway (any HTTP API in this account/region) to create streams and put log events.
    this.apiAccessLogGroup.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowApiGatewayPushLogs',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('apigateway.amazonaws.com')],
        actions: ['logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [`${this.apiAccessLogGroup.logGroupArn}:*`],
        conditions: {
          ArnLike: {
            'aws:SourceArn': `arn:aws:execute-api:${this.region}:${this.account}:*`,
          },
        },
      }),
    );

    this.apiAccessLogGroup.addSubscriptionFilter('AuditToS3', {
      filterPattern: logs.FilterPattern.allEvents(),
      destination: new logs_destinations.KinesisFirehoseDestination(deliveryStream),
    });

    new cdk.CfnOutput(this, 'AuditBucketName', { value: this.auditBucket.bucketName });
    new cdk.CfnOutput(this, 'ApiAccessLogGroupName', {
      value: this.apiAccessLogGroup.logGroupName,
    });
    new cdk.CfnOutput(this, 'AuditFirehoseName', {
      value: deliveryStream.deliveryStreamName,
    });
  }
}
