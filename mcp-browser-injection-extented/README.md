# MCP Browser - Injection Testing Edition

A Model Context Protocol (MCP) server for headless browser automation with **comprehensive injection testing capabilities**. This server allows AI assistants (LLM) to intelligently test web applications for security vulnerabilities using an iterative, adaptive approach.

## 🎯 Key Philosophy

**LLM is the brain, tool is the executor.**

This project empowers LLMs to perform intelligent security testing by:
- Providing a simple `browser_test_payload` tool that tests ONE payload at a time
- Including comprehensive injection testing guides in tool descriptions
- Letting the LLM generate payloads, analyze results, and adapt strategy iteratively
- No built-in payload libraries - LLM learns and creates its own

## ✨ Features

### Browser Automation
- **Multi-browser Support**: Chromium, Firefox, and WebKit browsers
- **Session Management**: Multiple browser sessions with unique IDs
- **Navigation**: Navigate to URLs with configurable wait conditions
- **Element Interaction**: Click, type, and interact with web elements
- **Screenshots**: Capture full page or element screenshots
- **Text Extraction**: Extract text content from web elements
- **Form Automation**: Fill out forms with multiple fields
- **JavaScript Execution**: Execute custom JavaScript on pages
- **Mobile Emulation**: Emulate mobile devices and orientations
- **PDF Generation**: Create PDFs from web pages
- **File Downloads**: Download files from web pages
- **Network Interception**: Monitor and mock network requests

### 🔥 Injection Testing (NEW!)
- **Single Payload Testing**: Test one payload at a time with detailed analysis
- **Intelligent Response Analysis**: Detect SQL errors, XSS reflection, time delays, WAF blocks
- **Comprehensive Guide**: 500+ lines of injection testing methodology in tool description
- **Iterative Workflow**: LLM generates payloads → tests → analyzes → adapts → repeats
- **All Injection Types**: SQL, XSS, XXE, SSTI, Command, LDAP, NoSQL
- **WAF Bypass Strategies**: Encoding techniques, obfuscation methods
- **No API Keys Required**: Fully functional without external dependencies

## 🚀 Installation

```bash
# 1. Clone repository
git clone <repository-url>
cd mcp-browser-injection-extented

# 2. Install dependencies
npm install

# 3. Install Playwright browsers
npm run install-browsers

# 4. Build the project
npm run build
```

## 📖 Usage

### Start the Server

```bash
# Production
npm start

# Development
npm run dev
```

### Configure MCP Client

Add to your MCP client configuration (e.g., Claude Desktop):

```json
{
  "mcpServers": {
    "mcp-browser": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-browser-injection-extented/dist/index.js"],
      "env": {
        "NODE_ENV": "production"
      },
      "description": "MCP Browser with injection testing capabilities"
    }
  }
}
```

## 🎯 Injection Testing Workflow

### How LLM Uses the Tool

The `browser_test_payload` tool includes a comprehensive guide that teaches the LLM:

#### 1. **SQL Injection Testing**
```
Phase 1: Test basic payload
→ browser_test_payload("#username", "'")

Phase 2: Analyze result
→ If SQL error → escalate to ' OR 1=1--
→ If blocked (403/406) → try encoding %27
→ If success → extract data with UNION SELECT

Phase 3: Iterate based on findings
→ Generate next payload adaptively
```

#### 2. **XSS Testing**
```
Phase 1: Test reflection
→ browser_test_payload("#comment", "<script>alert(1)</script>")

Phase 2: Check if reflected
→ If unencoded → HIGH CONFIDENCE XSS
→ If encoded → try bypass: <img src=x onerror=alert(1)>
→ If blocked → Unicode escape: \\u003cscript\\u003e
```

#### 3. **Command Injection**
```
Phase 1: Test basic commands
→ browser_test_payload("#input", "; ls")

Phase 2: If no output visible
→ Try time-based blind: ; sleep 5
→ If delay detected → escalate to data exfiltration
```

### Example LLM Conversation

```
User: "Test this login form for SQL injection: https://example.com/login"

LLM:
1. Navigate to the page
   → browser_navigate("https://example.com/login")

2. Test basic SQL injection
   → browser_test_payload("#username", "'")

3. [Analyzes response]
   Response: "SQL error: unclosed quotation"
   Confidence: HIGH
   Recommendation: "Try extracting data with UNION SELECT"

4. Escalate exploitation
   → browser_test_payload("#username", "' UNION SELECT NULL,NULL--")

5. [Analyzes again]
   Response: "Different content length, potential data extraction"

6. Document finding
   → browser_screenshot("sql_injection_evidence.png")
```

## 🔧 Available Tools

### Browser Navigation
- `browser_navigate` - Navigate to URLs
- `browser_get_page_info` - Get page information

### Element Interaction
- `browser_click` - Click elements
- `browser_type` - Type text
- `browser_wait_for_element` - Wait for elements
- `browser_fill_form` - Fill forms

### Content Extraction
- `browser_extract_text` - Extract text
- `browser_screenshot` - Take screenshots

### Page Manipulation
- `browser_scroll` - Scroll pages
- `browser_execute_script` - Execute JavaScript
- `browser_mobile_emulate` - Emulate mobile devices

### File Operations
- `browser_download_file` - Download files
- `browser_create_pdf` - Generate PDFs

### Network Control
- `browser_intercept_requests` - Monitor/mock requests

### **🔥 Security Testing**
- **`browser_test_payload`** - Test a single injection payload with detailed analysis

## 📚 Tool Description Guide

The `browser_test_payload` tool includes:

### Comprehensive Testing Methodologies:
- **SQL Injection**: Basic, time-based, UNION, blind, encoding, WAF bypass
- **XSS**: Reflection detection, event handlers, context-specific, polyglots
- **Command Injection**: Basic commands, blind techniques, time-based
- **SSTI**: Template detection, engine identification, RCE exploitation
- **NoSQL**: MongoDB operators, authentication bypass, regex injection
- **LDAP**: Wildcard injection, filter manipulation
- **XXE**: Basic, blind, parameter entities

### Encoding Reference:
- URL Encoding: `' → %27, < → %3C`
- HTML Entities: `' → &#39;, < → &#60;`
- Unicode Escaping: `' → \\u0027`
- Double Encoding: `' → %2527`

### WAF Bypass Techniques:
- Case variation: `UnIoN SeLeCt`
- Comment injection: `'/**/OR/**/1=1--`
- Newline injection: `'%0AOR%0A1=1--`
- Alternative syntax

## 🧠 Why This Approach?

### Traditional Approach (❌ Limited):
```
Tool has 50+ built-in payloads
→ LLM says "test this field"
→ Tool tests all 50 payloads automatically
→ Returns results
→ LLM doesn't learn or adapt
```

### Our Approach (✅ Intelligent):
```
LLM reads comprehensive guide
→ LLM generates first payload: '
→ Tool tests and returns analysis
→ LLM analyzes: "SQL error detected"
→ LLM adapts: generates ' OR 1=1--
→ Tool tests again
→ LLM escalates: generates ' UNION SELECT
→ Iterative, adaptive, intelligent testing
```

## 🎓 What LLM Learns

From the tool description, LLM learns:
- What each injection type is
- How to test systematically
- How to interpret responses
- When to escalate exploitation
- How to bypass WAF/filters
- Encoding techniques
- Context-specific payloads
- Blind testing strategies

## 🏗️ Architecture

```
┌─────────────────┐
│  LLM (Claude)   │  ← Reads tool description guide
│                 │  ← Generates payloads iteratively
│                 │  ← Analyzes results adaptively
└────────┬────────┘
         │
         ↓ Single payload at a time
┌─────────────────┐
│ browser_test    │  ← Executes ONE payload
│   _payload      │  ← Analyzes response
│                 │  ← Returns detailed analysis
└────────┬────────┘
         │
         ↓
┌─────────────────┐
│ PayloadAnalyzer │  ← SQL error detection
│                 │  ← XSS reflection detection
│                 │  ← Time-based detection
│                 │  ← WAF detection
│                 │  ← Status code analysis
└─────────────────┘
```

## 📊 Response Format

```json
{
  "success": true,
  "payload": "' OR 1=1--",
  "isVulnerable": true,
  "confidence": "high",
  "evidence": [
    "SQL error message detected: mysql",
    "Status code changed from 200 to 500"
  ],
  "detectedBehaviors": [
    "SQL_ERROR_MESSAGE",
    "SERVER_ERROR"
  ],
  "responseAnalysis": {
    "statusCode": 500,
    "responseTime": 1234,
    "baselineTime": 890,
    "timeDifference": 344,
    "responseLengthChange": 156
  },
  "recommendation": "✅ HIGH CONFIDENCE SQL INJECTION! Try extracting data with UNION SELECT or use time-based blind techniques."
}
```

## 🔒 Security Considerations

- Browser sessions run in headless mode
- No persistent cookies or storage
- Network requests can be intercepted
- JavaScript execution is sandboxed
- **This tool is for authorized security testing only**

## 🛠️ Development

```bash
# Build
npm run build

# Development mode
npm run dev

# Lint
npx eslint index.ts
```

## 📦 Dependencies

- **@modelcontextprotocol/sdk**: MCP protocol implementation
- **playwright**: Browser automation framework
- **typescript**: Type safety and compilation
- **tsx**: TypeScript execution in development

## ⚠️ Disclaimer

This tool is designed for **authorized security testing only**. Use it only on:
- Applications you own
- Systems you have explicit permission to test
- CTF challenges and educational environments
- Authorized penetration testing engagements

Unauthorized testing is illegal and unethical.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

[Add your license information here]

## 🙏 Support

For issues and questions, please open an issue on the repository.

---

**Built with ❤️ for intelligent, adaptive security testing**
