import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/recycles', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'sqli', 'csrf', 'date_manipulation', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'lsndr/juice-shop:master',
        databases: ['SQLite'],
        user_roles: {
          roles: ['customer', 'deluxe', 'accounting', 'admin']
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined,
      skipStaticParams: false
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Recycles`,
      body: {
        UserId: 1,
        AddressId: 1,
        quantity: 10,
        isPickup: true,
        date: '2023-10-01T00:00:00Z'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});