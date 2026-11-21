import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import * as lambdaEventSources from 'aws-cdk-lib/aws-lambda-event-sources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as msk from 'aws-cdk-lib/aws-msk';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as path from 'path';

export interface StreamingStackProps extends cdk.StackProps {}

/**
 * Kafka path: API Lambda → SQS → VPC Lambda (KafkaJS + MSK IAM) → Amazon MSK Serverless.
 * Bootstrap brokers are resolved at runtime (GetBootstrapBrokers); not exposed on the CFN resource.
 */
export class StreamingStack extends cdk.Stack {
  public readonly securityEventsQueue: sqs.Queue;
  public readonly mskCluster: msk.CfnServerlessCluster;

  constructor(scope: Construct, id: string, props?: StreamingStackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'StreamingVpc', {
      maxAzs: 2,
      natGateways: 1,
      restrictDefaultSecurityGroup: false,
    });

    const mskSg = new ec2.SecurityGroup(this, 'MskSecurityGroup', {
      vpc,
      description: 'MSK Serverless',
      allowAllOutbound: true,
    });

    const emitterSg = new ec2.SecurityGroup(this, 'EmitterSecurityGroup', {
      vpc,
      description: 'Kafka emitter Lambda',
      allowAllOutbound: true,
    });

    mskSg.addIngressRule(emitterSg, ec2.Port.tcp(9098), 'MSK SASL/IAM (TLS)');

    this.mskCluster = new msk.CfnServerlessCluster(this, 'SecurityEventsCluster', {
      clusterName: 'mlaitds-security-events',
      clientAuthentication: {
        sasl: { iam: { enabled: true } },
      },
      vpcConfigs: [
        {
          subnetIds: vpc.privateSubnets.map((s) => s.subnetId),
          securityGroups: [mskSg.securityGroupId],
        },
      ],
    });

    this.securityEventsQueue = new sqs.Queue(this, 'SecurityEventsQueue', {
      queueName: 'mlaitds-security-events',
      visibilityTimeout: cdk.Duration.seconds(120),
      retentionPeriod: cdk.Duration.days(4),
    });

    const emitter = new NodejsFunction(this, 'KafkaEmitter', {
      runtime: lambda.Runtime.NODEJS_20_X,
      entry: path.join(__dirname, '..', 'lambdas', 'kafka-emitter', 'index.ts'),
      handler: 'handler',
      timeout: cdk.Duration.seconds(120),
      memorySize: 512,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
      securityGroups: [emitterSg],
      environment: {
        MSK_CLUSTER_ARN: this.mskCluster.attrArn,
        KAFKA_TOPIC: 'mlaitds.security.events',
      },
      logRetention: logs.RetentionDays.TWO_WEEKS,
      bundling: {
        minify: true,
        sourceMap: true,
        target: 'node20',
      },
    });

    this.securityEventsQueue.grantConsumeMessages(emitter);

    emitter.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'KafkaDescribeBootstrap',
        effect: iam.Effect.ALLOW,
        actions: ['kafka:GetBootstrapBrokers', 'kafka:DescribeCluster', 'kafka:DescribeClusterV2'],
        resources: [this.mskCluster.attrArn],
      }),
    );

    emitter.addToRolePolicy(
      new iam.PolicyStatement({
        sid: 'KafkaClusterDataPlane',
        effect: iam.Effect.ALLOW,
        actions: [
          'kafka-cluster:Connect',
          'kafka-cluster:WriteData',
          'kafka-cluster:WriteDataIdempotent',
          'kafka-cluster:DescribeTopic',
          'kafka-cluster:CreateTopic',
          'kafka-cluster:AlterTopic',
        ],
        resources: [
          `arn:aws:kafka:${this.region}:${this.account}:cluster/*/*`,
          `arn:aws:kafka:${this.region}:${this.account}:topic/*/*/*`,
        ],
      }),
    );

    emitter.addEventSource(
      new lambdaEventSources.SqsEventSource(this.securityEventsQueue, {
        batchSize: 10,
        reportBatchItemFailures: true,
      }),
    );

    new cdk.CfnOutput(this, 'SecurityEventsQueueUrl', {
      value: this.securityEventsQueue.queueUrl,
    });
    new cdk.CfnOutput(this, 'MskClusterArn', { value: this.mskCluster.attrArn });
  }
}
