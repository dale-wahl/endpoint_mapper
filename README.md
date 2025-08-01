# Intelligent Endpoint Mapper

A Python-based tool that analyzes websites to discover and map their structure - both frontend pages and backend API endpoints. The tool generates a comprehensive structured representation showing how different parts of the system are connected.

---

## 📋 Features

### ✅ Base Requirements 

#### 1. **Site Crawling**
- ✅ Starts from root URL with recursive exploration
- ✅ Discovers internal links via HTML anchor tags
- ✅ Respects domain boundaries and implements polite crawling
- ✅ Rate limiting and timeout controls

#### 2. **Endpoint Identification** 
- ✅ Traverses all internal HTML pages identified
- ✅ Identifies HREF links and various SPA frameworks (Vue, React, Angular)
- ✅ Identifies REST API endpoints from multiple sources:
  - HTML form actions with intelligent API likelihood scoring
  - Inline JavaScript with context-aware method detection
  - External JavaScript files with authentication support
  - Template literals and dynamic URL construction patterns
  - Variable tracking for complex endpoint discovery

#### 3. **Relationship Mapping**
- ✅ Page-to-API relationship mapping
- ✅ Usage frequency analysis and source attribution
- ✅ Preserves semantic differences (trailing slash handling)
- ✅ Link relationship tracking and page depth analysis

#### 4. **Output Format**
- ✅ Rich, structured JSON output showing:
  - Discovered pages with metadata and status codes
  - API endpoints with methods, sources, and usage statistics
  - Page relationships and comprehensive link analysis
  - Script analysis with detailed endpoint detection

#### 5. **Interface**
- ✅ Full command-line interface with advanced options:
  - Authentication support (API keys, custom headers)
  - External script fetching capabilities
  - Verbose output and debugging modes
  - Configurable rate limiting and timeouts

---

## 🌟 Additional Features Implemented

### **Enhanced Endpoint Detection (Beyond Requirements)**
- **Template Literal Support**: Handles ES6 `${variable}` patterns in JavaScript
- **Variable Tracking**: Detects dynamic URL construction patterns
- **HTTP Method Context Detection**: Smart method inference from surrounding code
- **Advanced Form Analysis**: 
  - CSRF token detection
  - File upload identification
  - Button context analysis
  - AJAX vs standard form distinction

### **Production-Ready Features**
- **Authentication Integration**: Support for API keys and custom headers
- **Script Analysis**: Detailed tracking of external script fetching and analysis
- **Comprehensive Statistics**: Usage patterns, frequency analysis, relationship insights
- **Error Handling**: Robust exception handling with detailed error reporting
- **Containerization**: Full Docker support

---

## 🚀 Installation & Usage

### Using Docker (Recommended)

```bash
# Build the container
docker build -t endpoint-mapper .

# Run against test site
docker run endpoint-mapper https://qa-practice.netlify.app --max-pages 50 --verbose

# With authentication
docker run endpoint-mapper https://api.example.com --api-key your_key_here
```

### Local Installation

```bash
# Setup virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the tool
python main.py https://qa-practice.netlify.app
```

### Advanced Usage Examples

```bash
# Basic crawl with verbose output
python main.py https://qa-practice.netlify.app --verbose --max-pages 25

# With authentication, external script analysis, and spa detection
python main.py https://app.example.com \
  --api-key your_api_key \
  --fetch-external-scripts \
  --enable-spa \
  --output analysis.json

# Custom rate limiting for production sites
python main.py https://production-site.com \
  --delay 2 \
  --timeout 30 \
  --max-pages 100
```

---

## 📊 Sample Output Format

Our tool generates comprehensive JSON output that exceeds requirements:

```json
{
  "crawl_summary": {
    "base_url": "https://qa-practice.netlify.app",
    "pages_discovered": 15,
    "total_api_calls_found": 28,
    "unique_api_endpoints": 8,
    "pages_with_apis": 12,
    "avg_apis_per_page": 1.87
  },
  "pages": [
    {
      "url": "/login",
      "title": "User Login",
      "status_code": 200,
      "api_endpoints": [
        {
          "endpoint": "/api/auth/login",
          "method": "POST",
          "detected_in": "form_action",
          "api_likelihood": "high",
          "form_analysis": {
            "input_count": 3,
            "csrf_token": true,
            "file_uploads": false,
            "submit_buttons": ["sign in"]
          }
        }
      ],
      "scripts_analysis": {
        "external_scripts_found": 2,
        "scripts_analyzed": 2,
        "total_endpoints_from_scripts": 5
      }
    }
  ],
  "api_summary": {
    "/api/auth/login": {
      "used_by_pages": ["/login", "/register"],
      "http_methods": ["POST"],
      "detection_sources": ["form_action", "inline_script"],
      "usage_frequency": 3
    }
  },
  "script_analysis_summary": {
    "total_external_scripts": 15,
    "scripts_with_endpoints": 4,
    "external_scripts_fetched": 15,
    "external_scripts_failed": 0
  }
}
```

---

## 🏗️ Architecture & Code Quality

### **Modular Design**
```
src/
├── cli.py                 # Command interface & argument parsing
├── crawler.py             # Web crawling with authentication
├── endpoint_detector.py   # Advanced API detection 
├── relationship_mapper.py # Comprehensive relationship analysis  
└── output_formatter.py    # Rich JSON output generation
```

### **Key Technical Features**
- **Type Safety**: Full type hints throughout codebase
- **Error Handling**: Comprehensive exception handling with graceful degradation
- **Configurable**: Extensive CLI options for different use cases
- **Testable**: Modular design with clear separation of concerns
- **Production Ready**: Authentication, rate limiting, and robust error reporting

---

## 🧪 Testing

```bash
# Run full test suite
pytest tests/ -v

# Test specific components
pytest tests/test_endpoint_detector.py -v

# Test with coverage
pytest --cov=src tests/
```
---

## 🚫 Known Limitations

- **Single-Page Applications**: Heavy JavaScript SPAs may require dynamic analysis; detection for all SPA frameworks not implemented
- **Authentication Scope**: Currently supports API key auth; could be extended for OAuth/complex auth
- **Rate Limiting**: Implements polite crawling but not adaptive rate limiting
- **JavaScript Execution**: Static analysis only; no dynamic JavaScript execution
- **Maintanance**: Heavy reliant on regex and pattern matching which can change over time and thus require monitoring
- **External Scripts Analysis**: Currently limited to same domain JS; could be expanded to CSS (though not heavily used could contain API endpoints) and include external domain JS (which may have API endpoints)
- **Additional Options Needed**: Some hardcoded features would benefit from additionaly custimization (e.g., certain URL paths are excluded in crawls (see crawler.py: `_is_valid_url` method) and `--include-external-apis` only includes __certain__ external APIs based on heuristics).

---

## 🔮 Future Enhancement Opportunities

The following bonus features from the assessment could be added:
- **Dynamic JavaScript Execution**: Headless browser integration (Selenium/Playwright)
- **GraphQL Discovery**: Specialized GraphQL operation detection; Currently only attempts to identify endpoints in JS
- **Export Formats**: Database integration and, if demanded, other export formats such as PNG, HTML, CSV
