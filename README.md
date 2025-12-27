# Phisherman 🎣

> Production-ready phishing and malware URL analyzer service

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue.svg)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-red.svg)](https://redis.io)

Phisherman is a production-ready, plugin-based URL analyzer that combines multiple detection techniques to identify phishing and malware URLs with confidence scoring. Built with modern async Python stack for high performance and scalability.

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- Poetry
- Docker & Docker Compose
- PostgreSQL 16+
- Redis 7+

### Development Setup

```bash
# Clone and setup
git clone <repository-url>
cd phisherman

# Complete setup with secure .env generation
make dev-setup

# Start services
make up

# Run migrations
make migrate

# Start API server
make run
```

> **🔐 Security Note**: `make dev-setup` automatically generates a secure `.env` file with random passwords and secrets. Review and customize as needed.

### Demo Data Setup

```bash
# After initial setup, add demo data for victim cataloging
make seed

# This creates:
# - 7 victim companies (PayPal, Apple, Microsoft, Amazon, etc.)
# - 3 active phishing campaigns
# - Brand detection patterns for auto-classification

# Test the victim intelligence APIs
curl http://localhost:8000/api/v1/victims/stats
curl http://localhost:8000/api/v1/victims/industry/banking/trends
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd phisherman-frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at `http://localhost:3000`. Make sure the backend API is running on port 8000.

> **Note**: The frontend proxies `/api/v1/*` requests to the backend automatically.

### API Usage

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Analyze URL
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI       │    │   PostgreSQL    │    │      Redis      │
│   (API Layer)   │◄──►│   (Database)    │    │  (Cache/Queue)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                                               ▲
         ▼                                               │
┌─────────────────────────────────────────────────────────────────┐
│                    Analysis Engine                              │
├─────────────────┬─────────────────┬─────────────────────────────┤
│ DNS Resolver    │ RDAP/WHOIS     │ Blacklist Feeds             │
│ - A/AAAA/NS/MX  │ - Domain age   │ - PhishTank                 │
│ - CNAME chains  │ - Registrar    │ - OpenPhish                 │
│ - SaaS detection│ - Privacy proxy│ - URLHaus                   │
├─────────────────┼─────────────────┼─────────────────────────────┤
│ URL Heuristics  │ TLS Probe      │ Linear Scorer               │
│ - Punycode      │ - Cert issuer  │ - Weighted combination      │
│ - Entropy       │ - SANs         │ - Consensus adjustments     │
│ - Suspicious    │ - CT logs      │ - A/B test weights          │
└─────────────────┴─────────────────┴─────────────────────────────┘
         ▲
         │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Celery Worker   │    │ Celery Beat     │    │  Prometheus     │
│ (Enrichment)    │    │ (Scheduler)     │    │  (Metrics)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🧩 Core Components

### Analyzers

Plugin-based analyzers implementing `AnalyzerProtocol`:

- **DNS Resolver**: Analyzes DNS records, CNAME chains, **SaaS detection with PhishTank abuse data**
- **RDAP/WHOIS**: Domain age, registration data, registrar reputation
- **Blacklist Feeds**: Known bad URLs from PhishTank, OpenPhish, URLHaus
- **URL Heuristics**: Punycode, entropy, suspicious patterns, TLD risk
- **🆕 Victim Analyzer**: **Automatic company impersonation detection & cataloging**
- **TLS Probe**: Certificate validation, issuer reputation (placeholder)

#### 🆕 **PhishTank Intelligence Integration**

The DNS analyzer now includes real abuse statistics from PhishTank data (6,980 domains analyzed):

**📊 Top Abused Services:**
- `firebaseapp.com` + `web.app`: **4,326 cases** → Risk adjustment: **neutral** (0)
- `weebly.com` + `weeblysite.com`: **4,410 cases** → Risk adjustment: **+2** (high risk)
- `qrco.de` (QR codes): **2,548 cases** → Risk adjustment: **+15** (very high risk)
- `pages.dev` (Cloudflare): **374 cases** → Risk adjustment: **-2** (reduced from -5)

**🎯 Smart Risk Calibration:**
- **High-abuse services** get positive risk adjustments
- **Legitimate SaaS** with low abuse keep negative adjustments
- **URL shorteners** flagged with high risk scores
- **Real-world data** prevents false negatives

#### 🎯 **Victim Company Cataloging System**

**New B2B/B2C Intelligence Platform:**

- **🏢 Automatic Company Detection**: Identifies which companies are being impersonated
- **📊 Campaign Tracking**: Organizes phishing attempts into campaigns
- **🔍 Industry Analysis**: Trends and patterns by business sector
- **🎓 Educational Classification**: B2C learning examples identification
- **💼 Commercial Intelligence**: B2B threat intelligence database

**Key Features:**
- **Pattern Recognition**: Auto-detects PayPal, Apple, Microsoft, Amazon, etc.
- **Deception Techniques**: Typosquatting, subdomain abuse, domain squatting analysis
- **Risk Scoring**: Company-specific threat levels and targeting frequency
- **Campaign Clustering**: Groups related attacks for threat intelligence

### Scoring System

- **Linear Scorer**: Weighted combination with configurable weights
- **Consensus Adjustments**: Bonus/penalty based on analyzer agreement
- **A/B Testing**: Multiple weight configurations for experimentation

### Background Tasks

- **Feed Refresh**: Periodic updates from threat intelligence sources
- **Enrichment**: Async WHOIS/RDAP queries for detailed analysis
- **Maintenance**: Cleanup old entries, cache invalidation

## 📊 API Reference

### POST /analyze

Analyze a URL for phishing and malware indicators.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "url": "https://example.com",
  "malicious": false,
  "score": 15.5,
  "confidence": 0.85,
  "labels": ["established_domain", "legitimate_tld"],
  "evidence": {
    "dns_resolver": {"a_records": [{"value": "93.184.216.34", "ttl": 86400}]},
    "rdap_whois": {"domain_age_days": 12450},
    "url_heuristics": {"entropy": 3.2, "domain_length": 11}
  },
  "analyzers": [...],
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-01T12:00:00Z",
  "processing_time_ms": 245.6,
  "cached": false,
  "version": "0.1.0"
}
```

### GET /healthz

Comprehensive health check with dependency status.

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "uptime_seconds": 3600,
  "database": true,
  "redis": true,
  "celery": true
}
```

## 🆕 Victim Intelligence APIs

### GET /victims/

List victim companies with filtering and pagination.

**Query Parameters:**
- `industry`: Filter by industry (banking, technology, ecommerce, etc.)
- `min_risk_score`: Minimum risk score (0-100)
- `search`: Search company names
- `sort_by`: Sort field (risk_score, name, total_phishing_urls)
- `limit`: Results per page (max 100)

**Response:**
```json
[
  {
    "id": "uuid",
    "name": "PayPal",
    "industry": "banking",
    "total_phishing_urls": 1247,
    "active_campaigns": 12,
    "risk_score": 85.0,
    "official_domains": ["paypal.com", "paypal.me"],
    "brand_keywords": ["paypal", "pay-pal"]
  }
]
```

### GET /victims/stats

Get comprehensive victim statistics and trends.

**Response:**
```json
{
  "total_companies": 127,
  "total_campaigns": 43,
  "total_phishing_urls": 8924,
  "by_industry": {
    "banking": 45,
    "technology": 38,
    "ecommerce": 22
  },
  "trending_victims": [
    {
      "name": "PayPal",
      "industry": "banking",
      "recent_urls": 89
    }
  ]
}
```

### GET /victims/{company_id}/campaigns

Get phishing campaigns targeting a specific company.

### GET /victims/industry/{industry}/trends

Get industry-specific phishing trends and threat intelligence.

## 🔧 Configuration

### Environment Variables

Generate secure `.env` file automatically:

```bash
# Generate .env with secure random secrets
make generate-env

# Or manually copy and customize
cp .env-example .env
```

Key configuration options:

```bash
# Application
ENVIRONMENT=development
SECRET_KEY=auto-generated-secure-key
DATABASE_URL=postgresql://user:secure-password@localhost:5432/phisherman
REDIS_URL=redis://localhost:6379

# Rate Limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=100

# External APIs (add your keys)
VIRUSTOTAL_API_KEY=your-key-here
SHODAN_API_KEY=your-key-here

# Feed refresh intervals (minutes)
PHISHTANK_REFRESH_INTERVAL=15
OPENPHISH_REFRESH_INTERVAL=15
URLHAUS_REFRESH_INTERVAL=15
```

> **🔒 Production**: Use `env.production.example` as template for production deployments with stronger security settings.

### Scoring Weights

Configure analyzer weights in `configs/weights.yaml`:

```yaml
scorers:
  linear:
    weights:
      blacklist_feeds: 0.9
      dns_resolver: 0.8
      rdap_whois: 0.7
      url_heuristics: 0.6
      tls_probe: 0.4
    thresholds:
      low: 25.0
      medium: 50.0
      high: 75.0
```

### SaaS Provider Catalog

Enhanced `configs/saas_catalog.yaml` with **PhishTank abuse statistics**:

```yaml
providers:
  google:
    name: "Google Cloud / Firebase"
    patterns:
      cnames: ["firebaseapp.com", "web.app", "appspot.com"]
    # PhishTank data: 4,326 combined abuse cases
    risk_adjustment: 0  # Neutral due to very high abuse
    abuse_frequency: 4326
    confidence: 0.6

high_risk_services:
  url_shorteners:
    qrco:
      patterns: ["qrco.de"]
      abuse_frequency: 2548
      risk_adjustment: 15  # High risk
      confidence: 0.9
```

## 🧪 Development

### Commands

```bash
make install      # Install dependencies
make generate-env # Generate secure .env file
make dev-setup    # Complete development setup
make run          # Run API server
make worker       # Run Celery worker
make beat         # Run Celery scheduler
make test         # Run test suite
make lint         # Run linting
make fmt          # Format code
make migrate      # Run DB migrations
make seed         # Seed victim cataloging data (companies, campaigns)
make up           # Start all services
make down         # Stop services
make frontend-install # Install frontend dependencies
make frontend     # Run frontend dev server (localhost:3000)
```

### Testing

```bash
# Run all tests
make test

# Run specific test file
poetry run pytest tests/test_analyzers.py -v

# Run with coverage
poetry run pytest --cov=phisherman --cov-report=html
```

### Adding New Analyzers

1. Create analyzer in `phisherman/analyzers/`
2. Implement `AnalyzerProtocol`
3. Register in `AnalysisEngine`
4. Add tests
5. Update configuration weights

Example:

```python
from phisherman.analyzers.protocol import BaseAnalyzer, AnalyzerResult

class MyAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "my_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def weight(self) -> float:
        return 0.7

    async def _analyze_impl(self, url: str) -> AnalyzerResult:
        # Implement analysis logic
        return AnalyzerResult(
            analyzer_name=self.name,
            risk_score=score,
            confidence=confidence,
            labels=labels,
            evidence=evidence,
            execution_time_ms=0.0,
        )
```

## 🚀 Deployment

### Docker Production

```bash
# Build image
make build

# Run with production config
docker run -p 8000:8000 --env-file .env phisherman:latest
```

### Docker Compose

```bash
# Production stack
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Kubernetes

See `k8s/` directory for Kubernetes manifests (TODO).

## 📊 Monitoring

### Metrics

Prometheus metrics available at `/metrics`:

- `http_requests_total` - Request counts by endpoint/status
- `http_request_duration_seconds` - Request latency
- `url_analyses_total` - Analysis counts by result

### Observability

- **Logs**: Structured JSON logging
- **Tracing**: OpenTelemetry support (optional)
- **Health**: `/health` and `/healthz` endpoints
- **Grafana**: Dashboard templates in `configs/grafana/`

## 🔒 Security

### Security Features

- **🔐 Secure Configuration**: Auto-generated random secrets and passwords
- **🛡️ Input Validation**: Strict URL validation and normalization
- **⏱️ Rate Limiting**: Token bucket algorithm with Redis
- **🕒 Timeout Protection**: All network requests have timeouts
- **🚫 Error Handling**: No stack trace exposure to clients
- **💾 SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **📝 Environment Security**: `.env` files auto-excluded from git
- **🔍 Static Analysis**: Pre-commit hooks with security linting

### Configuration Security

```bash
# Generate secure config automatically
make generate-env  # Creates .env with random 64-char secrets

# Production template with enhanced security
cp env.production.example .env  # For production deployments
```

### Production Security Checklist

- [ ] Use generated secrets (never default passwords)
- [ ] Enable HTTPS/TLS with valid certificates
- [ ] Set strong `SECRET_KEY` (64+ characters)
- [ ] Configure `ALLOWED_HOSTS` for your domains
- [ ] Disable debug mode (`DEBUG=false`)
- [ ] Use authentication for admin/metrics endpoints
- [ ] Enable request logging and monitoring
- [ ] Regular security updates and dependency scanning
- [ ] Network segmentation (DB/Redis not public)
- [ ] Rate limiting tuned for expected load

### Security Headers

The application automatically sets:
- CORS policies based on `ALLOWED_HOSTS`
- Content Security Policy headers
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Make changes and add tests
4. Run checks: `make check`
5. Commit changes: `git commit -m 'Add amazing feature'`
6. Push branch: `git push origin feature/amazing-feature`
7. Open Pull Request

## 📝 TODO / Roadmap

### Core Platform
- [ ] TLS certificate analyzer implementation
- [ ] Machine learning scorer option
- [ ] GraphQL API
- [ ] Kubernetes manifests
- [ ] Advanced caching strategies
- [ ] Multi-region deployment support

### B2C Educational Platform
- [ ] **Interactive phishing detection training**
- [ ] **Visual comparison tools (legitimate vs. phishing)**
- [ ] **Browser extension for real-time warnings**
- [ ] **Gamified learning modules**
- [ ] **Community reporting system**
- [ ] **Mobile app for phishing awareness**

### B2B Intelligence Platform
- [ ] **Enterprise threat intelligence dashboards**
- [ ] **Brand protection monitoring**
- [ ] **Automated takedown integration**
- [ ] **Custom industry reports**
- [ ] **API rate limiting and billing**
- [ ] **Multi-tenant architecture**
- [ ] **Slack/Teams integration**
- [ ] **SIEM connectors (Splunk, QRadar)**

### Advanced Analytics
- [ ] **ML-powered campaign attribution**
- [ ] **Threat actor profiling**
- [ ] **Predictive threat modeling**
- [ ] **Geographic attack patterns**
- [ ] **Real-time WebSocket alerts**
- [ ] **Threat landscape reports**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [PhishTank](https://phishtank.org/) - Community phishing URL feed
- [OpenPhish](https://openphish.com/) - Phishing intelligence feed
- [URLhaus](https://urlhaus.abuse.ch/) - Malware URL sharing
- [Abuse.ch](https://abuse.ch/) - Threat intelligence community

---

**⚠️ Disclaimer**: Phisherman is for legitimate security research and protection only. Users are responsible for compliance with applicable laws and regulations.
