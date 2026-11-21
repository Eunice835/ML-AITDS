import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

export interface StateStackProps extends cdk.StackProps {}

/** DynamoDB tables for authority, budgets, velocity, and request indexing. Extend later for DetectionStack consumers. */
export class StateStack extends cdk.Stack {
  public readonly authorityStateTable: dynamodb.Table;
  public readonly abuseBudgetTable: dynamodb.Table;
  public readonly authorityVelocityTable: dynamodb.Table;
  public readonly requestLogIndexTable: dynamodb.Table;

  constructor(scope: Construct, id: string, props?: StateStackProps) {
    super(scope, id, props);

    const removal = cdk.RemovalPolicy.DESTROY;

    this.authorityStateTable = new dynamodb.Table(this, 'AuthorityState', {
      tableName: 'mlaitds-authority-state',
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: removal,
    });

    this.abuseBudgetTable = new dynamodb.Table(this, 'AbuseBudget', {
      tableName: 'mlaitds-abuse-budget',
      partitionKey: { name: 'principalKey', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'windowId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: removal,
    });

    this.authorityVelocityTable = new dynamodb.Table(this, 'AuthorityVelocity', {
      tableName: 'mlaitds-authority-velocity',
      partitionKey: { name: 'principalKey', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: removal,
    });

    this.requestLogIndexTable = new dynamodb.Table(this, 'RequestLogIndex', {
      tableName: 'mlaitds-request-log-index',
      partitionKey: { name: 'requestId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'ts', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      removalPolicy: removal,
    });

    new cdk.CfnOutput(this, 'AuthorityStateTableName', {
      value: this.authorityStateTable.tableName,
    });
    new cdk.CfnOutput(this, 'AbuseBudgetTableName', {
      value: this.abuseBudgetTable.tableName,
    });
    new cdk.CfnOutput(this, 'AuthorityVelocityTableName', {
      value: this.authorityVelocityTable.tableName,
    });
    new cdk.CfnOutput(this, 'RequestLogIndexTableName', {
      value: this.requestLogIndexTable.tableName,
    });
  }
}
