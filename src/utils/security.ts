export interface HeaderResult {
  name: string;
  value: string | null;
  status: 'secure' | 'insecure' | 'warning' | 'missing' | 'info';
  description: string;
  recommendation?: string;
}

export interface SecurityAnalysisReport {
  score: number; // 0-100
  results: HeaderResult[];
}

export function parseHeaders(raw: string): Record<string, string> {
  const lines = raw.split('\n');
  const headers: Record<string, string> = {};
  
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    
    // Ignore HTTP status line like "HTTP/1.1 200 OK"
    if (line.toUpperCase().startsWith('HTTP/')) continue;
    
    const separatorIdx = line.indexOf(':');
    if (separatorIdx === -1) continue;
    
    const key = line.slice(0, separatorIdx).trim().toLowerCase();
    const value = line.slice(separatorIdx + 1).trim();
    if (key) {
      headers[key] = value;
    }
  }
  
  return headers;
}

const SECURITY_HEADERS = [
  {
    name: 'Strict-Transport-Security',
    description: 'Enforces secure (HTTP over SSL/TLS) connections to the server.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) {
        return {
          name: 'Strict-Transport-Security', value: val, status: 'missing',
          description: 'Enforces secure (HTTP over SSL/TLS) connections.',
          recommendation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains".'
        };
      }
      if (val.includes('max-age') && parseInt(val.match(/max-age=(\d+)/)?.[1] || '0') >= 31536000) {
        return { name: 'Strict-Transport-Security', value: val, status: 'secure', description: 'HSTS is properly configured with a good max-age.' };
      }
      return { 
        name: 'Strict-Transport-Security', 
        value: val, 
        status: 'warning', 
        description: 'HSTS is present but max-age might be too short or incorrectly formatted.', 
        recommendation: 'Ensure max-age is at least 31536000 (1 year).' 
      };
    }
  },
  {
    name: 'Content-Security-Policy',
    description: 'Prevents cross-site scripting (XSS) and other code injection attacks.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) return { name: 'Content-Security-Policy', value: val, status: 'missing', description: 'Prevents XSS and data injection.', recommendation: "Implement a strict CSP restricting sources, e.g., default-src 'self'." };
      return { name: 'Content-Security-Policy', value: val, status: 'secure', description: 'CSP is present. Ensure it tightly restricts external sources.' };
    }
  },
  {
    name: 'X-Frame-Options',
    description: 'Protects against clickjacking attacks by preventing inline frames.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) return { name: 'X-Frame-Options', value: val, status: 'missing', description: 'Protects against clickjacking.', recommendation: 'Add "X-Frame-Options: DENY" or "SAMEORIGIN".' };
      if (['deny', 'sameorigin'].includes(val.toLowerCase())) return { name: 'X-Frame-Options', value: val, status: 'secure', description: 'Correctly configured to prevent clickjacking.' };
      return { name: 'X-Frame-Options', value: val, status: 'insecure', description: 'Invalid value for X-Frame-Options.', recommendation: 'Use DENY or SAMEORIGIN.' };
    }
  },
  {
    name: 'X-Content-Type-Options',
    description: 'Prevents the browser from interpreting files as a different MIME type.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) return { name: 'X-Content-Type-Options', value: val, status: 'missing', description: 'Prevents MIME-sniffing.', recommendation: 'Add "X-Content-Type-Options: nosniff".' };
      if (val.toLowerCase() === 'nosniff') return { name: 'X-Content-Type-Options', value: val, status: 'secure', description: 'MIME-sniffing prevention is active.' };
      return { name: 'X-Content-Type-Options', value: val, status: 'insecure', description: 'Invalid value.', recommendation: 'Set to "nosniff".' };
    }
  },
  {
    name: 'Referrer-Policy',
    description: 'Controls how much referring information is included with requests.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) return { name: 'Referrer-Policy', value: val, status: 'missing', description: 'Controls referrer information.', recommendation: 'Add "Referrer-Policy: strict-origin-when-cross-origin".' };
      return { name: 'Referrer-Policy', value: val, status: 'secure', description: 'Referrer-Policy is configured.' };
    }
  },
  {
    name: 'Permissions-Policy',
    description: 'Provides a mechanism to allow or deny the use of browser features.',
    evaluate: (val: string | null): HeaderResult => {
      if (!val) return { name: 'Permissions-Policy', value: val, status: 'warning', description: 'Controls access to browser features.', recommendation: 'Restrict features like geolocation, microphone, and camera if not needed.' };
      return { name: 'Permissions-Policy', value: val, status: 'secure', description: 'Permissions-Policy is implemented.' };
    }
  }
];

export function analyzeHeaders(raw: string): SecurityAnalysisReport {
  const parsed = parseHeaders(raw);
  const results: HeaderResult[] = [];
  
  let score = 100;
  let deductions = 0;
  
  for (const rule of SECURITY_HEADERS) {
    const val = parsed[rule.name.toLowerCase()] || null;
    const res = rule.evaluate(val);
    results.push(res);
    
    if (res.status === 'missing') deductions += 15;
    else if (res.status === 'warning') deductions += 5;
    else if (res.status === 'insecure') deductions += 20;
  }
  
  // Check for informational headers that expose server details
  const infoHeaders = [
    { key: 'server', description: 'Exposes server software details.' },
    { key: 'x-powered-by', description: 'Exposes backend technology.' },
    { key: 'x-aspnet-version', description: 'Exposes ASP.NET version.' }
  ];
  
  for (const info of infoHeaders) {
    if (parsed[info.key]) {
      results.push({
        name: info.key,
        value: parsed[info.key],
        status: 'insecure',
        description: info.description,
        recommendation: `Remove the '${info.key}' header to prevent information leakage.`
      });
      deductions += 10;
    }
  }
  
  score = Math.max(0, 100 - deductions);
  return { score, results };
}
