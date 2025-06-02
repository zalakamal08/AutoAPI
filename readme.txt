# AI-Powered API Pentesting Tool

## Requirements (requirements.txt)

```
langchain>=0.1.0
langchain-google-genai>=0.0.6
google-generativeai>=0.3.0
requests>=2.31.0
```

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Get Gemini API Key
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Set it as environment variable:

**Linux/Mac:**
```bash
export GEMINI_API_KEY="your-api-key-here"
```

**Windows:**
```cmd
set GEMINI_API_KEY=your-api-key-here
```

### 3. Usage Examples

#### Method 1: Using curl.txt file
```bash
# Create curl.txt with your curl command
echo 'curl -X POST https://api.example.com/login -d "username=admin&password=test"' > curl.txt

# Run the tool
python api_pentest_tool.py
```

#### Method 2: Command line argument
```bash
python api_pentest_tool.py "curl -X POST https://api.example.com/login -d 'username=admin&password=test'"
```

#### Method 3: From file
```bash
python api_pentest_tool.py mycurl.txt
```

## Features

### 🤖 AI-Powered Analysis
- **Dynamic Payload Generation**: Uses Gemini to create contextual payloads based on API analysis
- **Intelligent Request Modification**: Automatically places payloads in optimal locations
- **Smart Response Analysis**: AI analyzes responses to detect vulnerabilities

### 🔍 Security Tests Included
1. **SQL Injection** - Database query manipulation
2. **Cross-Site Scripting (XSS)** - Script injection attacks
3. **Authentication Bypass** - Token/session manipulation
4. **Parameter Pollution** - HTTP parameter pollution
5. **Directory Traversal** - Path traversal attacks
6. **Command Injection** - OS command execution

### 📊 Advanced Reporting
- **Vulnerability Severity Rating** - Critical/High/Medium/Low
- **Professional Report Generation** - Executive summary and technical details
- **Evidence Collection** - Captures request/response pairs
- **Risk Assessment** - AI-generated risk analysis

## Key Improvements Over Static Tools

### 1. Context-Aware Testing
```python
# Instead of static payloads like:
payloads = ["' OR 1=1--", "admin'--"]

# AI generates contextual payloads:
# For a banking API: "'; DROP TABLE transactions; --"
# For a user API: "' UNION SELECT password FROM users--"
```

### 2. Intelligent Payload Placement
- Analyzes API structure to determine optimal injection points
- Considers authentication mechanisms
- Adapts to different data formats (JSON, form-data, XML)

### 3. Smart Response Analysis
- Detects vulnerability indicators beyond simple pattern matching
- Considers context and business logic
- Reduces false positives through AI analysis

## Sample Output

```
🚀 Starting AI-Powered API Security Testing
==================================================

🔍 Running SQL Injection tests...
📝 Generated 8 payloads
   Testing payload 1/8...
   Testing payload 2/8...
   ⚠️  Potential vulnerability found! Severity: high
   Testing payload 3/8...
   ...

🔍 Running XSS tests...
📝 Generated 6 payloads
   Testing payload 1/6...
   ...

📊 Testing completed! Total potential vulnerabilities: 3

📄 Generating security report...
📄 Report saved to: security_report_1234567890.txt
```

## Configuration Options

### Model Selection
```python
# Use different Gemini models
tester = APISecurityTester(
    gemini_api_key="your-key", 
    model_name="gemini-pro"  # or "gemini-pro-vision"
)
```

### Custom Test Types
You can extend the tool by adding custom test types in the `test_types` list:

```python
test_types = [
    "sql_injection",
    "xss",
    "authentication_bypass",
    "parameter_pollution",
    "directory_traversal", 
    "command_injection",
    "custom_test_type"  # Add your own
]
```

## Security Best Practices

⚠️ **Important**: Only use this tool on:
- Your own applications
- Applications you have explicit permission to test
- Bug bounty programs where you're authorized

## Troubleshooting

### Common Issues

1. **API Key Error**
   ```
   Error: Please set GEMINI_API_KEY environment variable
   ```
   Solution: Set the environment variable correctly

2. **Rate Limiting**
   - The tool includes delays between requests
   - Increase delays if you hit rate limits

3. **Network Timeouts**
   - Tool has 30-second timeout per request
   - Adjust in `execute_curl()` method if needed

### Debug Mode
Add debug prints to see what the AI is generating:

```python
print(f"Generated payload: {payload}")
print(f"Modified curl: {modified_curl}")
```

## Advantages Over Traditional Tools

| Feature | Traditional Tools | AI-Powered Tool |
|---------|------------------|-----------------|
| Payload Generation | Static lists | Dynamic, contextual |
| Response Analysis | Pattern matching | Intelligent analysis |
| Adaptability | Fixed rules | Learns from API structure |
| False Positives | High | Reduced through AI |
| Reporting | Basic | Professional, detailed |

This tool represents the next generation of security testing - leveraging AI to make pentesting more intelligent, accurate, and efficient.