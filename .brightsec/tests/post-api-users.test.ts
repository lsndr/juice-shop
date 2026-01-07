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

test('POST /api/users', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['xss', 'sqli', 'csrf', 'proto_pollution', 'secret_tokens'],
      attackParamLocations: [AttackParamLocation.BODY],
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
      method: HttpMethod.POST,
      url: `${baseUrl}/api/Users`,
      body: {
        email: 'user@example.com',
        password: 'securePassword123',
        passwordRepeat: 'securePassword123'
      },
      headers: { 'Content-Type': 'application/json' }
    });
});