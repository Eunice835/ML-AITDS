import type { SQSEvent, SQSBatchResponse } from 'aws-lambda';
import { KafkaClient, GetBootstrapBrokersCommand } from '@aws-sdk/client-kafka';
import { Kafka } from 'kafkajs';
import { createMechanism } from '@jm18457/kafkajs-msk-iam-authentication-mechanism';

const TOPIC = process.env.KAFKA_TOPIC ?? 'mlaitds.security.events';
const region = process.env.AWS_REGION ?? 'us-east-1';

let producerPromise: ReturnType<typeof connectProducer> | null = null;

function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env ${name}`);
  return v;
}

async function connectProducer() {
  const clusterArn = requireEnv('MSK_CLUSTER_ARN');
  const kafkaControl = new KafkaClient({ region });
  const boot = await kafkaControl.send(new GetBootstrapBrokersCommand({ ClusterArn: clusterArn }));
  const brokerList = (boot.BootstrapBrokerStringSaslIam ?? '')
    .split(',')
    .map((b) => b.trim())
    .filter(Boolean);
  if (brokerList.length === 0) {
    throw new Error('BootstrapBrokerStringSaslIam empty; check MSK cluster + IAM');
  }

  const kafka = new Kafka({
    clientId: 'mlaitds-kafka-emitter',
    brokers: brokerList,
    ssl: true,
    sasl: createMechanism({ region }),
  });

  const admin = kafka.admin();
  await admin.connect();
  try {
    await admin.createTopics({
      topics: [{ topic: TOPIC, numPartitions: 3 }],
      waitForLeaders: true,
    });
  } catch {
    // Topic may already exist; MSK Serverless manages replication
  }
  await admin.disconnect();

  const producer = kafka.producer();
  await producer.connect();
  return producer;
}

function messageKey(body: string): string {
  try {
    const o = JSON.parse(body) as { sub?: string };
    if (o.sub && typeof o.sub === 'string') return o.sub.slice(0, 128);
  } catch {
    /* ignore */
  }
  return 'unknown';
}

export async function handler(event: SQSEvent): Promise<SQSBatchResponse> {
  if (!producerPromise) producerPromise = connectProducer();
  const producer = await producerPromise;

  const failures: { itemIdentifier: string }[] = [];

  for (const record of event.Records) {
    try {
      await producer.send({
        topic: TOPIC,
        messages: [{ key: messageKey(record.body), value: record.body }],
      });
    } catch {
      failures.push({ itemIdentifier: record.messageId });
    }
  }

  return { batchItemFailures: failures };
}
