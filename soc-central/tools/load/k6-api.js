// k6 load test for the SOC Central API read path.
// Run:  k6 run -e BASE=http://localhost:8000 tools/load/k6-api.js
// Or:   docker run --rm -i --network host -e BASE=http://localhost:8000 \
//         -v "$PWD/tools/load:/s" grafana/k6 run /s/k6-api.js
//
// Characterizes the endpoints the analyst console hits hardest, with SLA thresholds
// (p95 latency + error rate) so a regression shows up as a failed run in CI.
import http from 'k6/http';
import { check, sleep, group } from 'k6';

const BASE = __ENV.BASE || 'http://localhost:8000';

export const options = {
  scenarios: {
    steady: { executor: 'constant-vus', vus: Number(__ENV.VUS || 10), duration: __ENV.DURATION || '30s' },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],            // < 1% errors
    http_req_duration: ['p(95)<400'],          // 95th percentile under 400ms
    'http_req_duration{ep:ranking}': ['p(95)<500'],
  },
};

const READS = [
  ['ranking', '/risk/ranking?limit=50'],
  ['stats', '/stats/summary'],
  ['assets', '/assets'],
  ['compliance', '/compliance/summary'],
  ['detections', '/detections/recent?limit=30'],
  ['notifications', '/notifications'],
];

export default function () {
  group('reads', () => {
    for (const [ep, path] of READS) {
      const res = http.get(`${BASE}${path}`, { tags: { ep } });
      check(res, { [`${ep} 200`]: (r) => r.status === 200 });
    }
  });
  sleep(1);
}
