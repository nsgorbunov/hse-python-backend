import http from 'k6/http';

const baseUrl = 'http://localhost:8000';

export const options = {
  scenarios: {
    constant_request_rate: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      stages: [
        { target: 120000, duration: '20m' },
      ],
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
  },
};


export default function () {
  const url = `${baseUrl}/user-get?id=2`;

  const headers = {
      'Accept': 'application/json',
      'Authorization': 'Basic dXNlcjpzZWNyZXRfcGFzc3dvcmRfMTIz',
  };

  const payload = null;

  const res = http.post(url, payload, { headers: headers });
}