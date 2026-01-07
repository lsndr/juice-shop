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

test('PUT /api/addresses/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'sqli', 'xss', 'csrf', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.PATH],
      starMetadata: {
        code_source: 'lsndr/juice-shop:master',
        databases: ['SQLite'],
        user_roles: {
          roles: ['customer', 'deluxe', 'accounting', 'admin']
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/addresses/1`,
      body: {
        UserId: 1,
        fullName: 'John Doe',
        mobileNum: 1234567890,
        zipCode: '12345',
        streetAddress: '123 Main St',
        city: 'Metropolis',
        state: 'NY',
        country: 'USA'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});