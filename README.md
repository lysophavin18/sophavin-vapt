# S VAPT Platform

> **Enterprise-Grade Vulnerability Assessment and Penetration Testing Platform**

A production-ready, containerized vulnerability scanning platform that orchestrates multiple security tools through a unified interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.12-blue.svg)
![React](https://img.shields.io/badge/react-18.2-61dafb.svg)

## Features

### Core Capabilities
- **Multi-Tool Orchestration**: 21 security tools across network, web, container, cloud, IaC, Kubernetes, and API security
- **Queue-Based Execution**: Celery-powered scan queue with resource-aware scheduling
- **Real-Time Progress**: Live scan progress tracking and WebSocket updates
- **Finding Aggregation**: Centralized findings with deduplication and severity scoring
- **Report Generation**: Professional PDF, HTML, and JSON reports
- **AI-Powered Analysis**: Intelligent vulnerability analysis with OpenAI, Anthropic, or Ollama

### Security Features
- **Role-Based Access Control**: Admin, Manager, and Analyst roles
- **Scan Approval Workflow**: Optional approval for external targets
- **Audit Logging**: Complete audit trail of all actions
- **Network Isolation**: Scanners run in isolated Docker networks

### Technical Features
- **Microservices Architecture**: Scalable, containerized services
- **Async API**: High-performance FastAPI backend
- **Modern UI**: React 18 with Material-UI
- **Observability**: Prometheus metrics and structured logging

## AI Integration

Noovastack-VAPT includes an AI-powered security assistant that provides intelligent analysis of scan results.

### Supported Providers

| Provider | Model | Configuration |
|----------|-------|---------------|
| **OpenAI** | GPT-4o (default) | `OPENAI_API_KEY` |
| **Anthropic** | Claude Sonnet 4 | `ANTHROPIC_API_KEY` |
| **Ollama** | Llama 3.2 (local) | `OLLAMA_HOST` |

### AI Features

- **Scan Analysis**: Automated vulnerability prioritization and insights
- **Remediation Guidance**: Step-by-step fix instructions with commands
- **Threat Intelligence**: MITRE ATT&CK mapping and threat actor analysis
- **Report Generation**: AI-generated executive summaries and technical reports
- **Interactive Chat**: Ask questions about findings in natural language

### Configuration

```bash
# Add to .env file

# OpenAI (recommended)
AI_PROVIDER=openai
OPENAI_API_KEY=sk-your-api-key
OPENAI_MODEL=gpt-4o

# OR Anthropic
AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=your-api-key
ANTHROPIC_MODEL=claude-sonnet-4-20250514

# OR Ollama (local, free)
AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Optional settings
AI_MAX_TOKENS=4096
AI_TEMPERATURE=0.3
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/ai/chat` | POST | Interactive chat with context |
| `/api/v1/ai/chat/stream` | POST | Streaming chat response (SSE) |
| `/api/v1/ai/analyze/{scan_id}` | POST | AI analysis of scan results |
| `/api/v1/ai/remediation` | POST | Get remediation for a finding |
| `/api/v1/ai/threat-intel` | POST | Threat intelligence analysis |
| `/api/v1/ai/report-section` | POST | Generate report sections |
| `/api/v1/ai/providers` | GET | List configured providers |

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose
- 8 GB RAM minimum
- 50 GB disk space

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/noovastack-vapt.git
cd noovastack-vapt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start platform
docker compose up -d

# Check status
docker compose ps
```

### Access
- **Web UI**: http://localhost
- **API Docs**: http://localhost/docs
- **Default Login**: admin / ChangeMe123!

> ⚠️ Change the default password immediately!

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Nginx (Reverse Proxy)                │
└─────────────────────────────────────────────────────────────┘
                    │                      │
        ┌───────────┴───────────┐  ┌──────┴──────┐
        │    React Frontend     │  │ FastAPI API │
        │    (Port 3000)        │  │ (Port 8000) │
        └───────────────────────┘  └──────┬──────┘
                                          │
              ┌───────────────────────────┼───────────────────┐
              │                           │                   │
        ┌─────┴─────┐              ┌──────┴──────┐    ┌──────┴──────┐
        │ PostgreSQL│              │    Redis    │    │   Celery    │
        │ (Database)│              │   (Queue)   │    │(Orchestrator│
        └───────────┘              └─────────────┘    └──────┬──────┘
                                                             │
        ┌────────────────────────────────────────────────────┘
        │
┌───────┴───────────────────────────────────────────────────────────┐
│                    Scanner Network (Isolated)                      │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │ OpenVAS │ │ Nuclei  │ │  ZAP    │ │  Nmap   │ │ Nikto   │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │ SQLmap  │ │ Trivy   │ │ Clair   │ │ Falco   │ │ Prowler │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │ Checkov │ │Terrascan│ │KubeHuntr│ │KubeBench│ │ Arjun   │     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐     │
│  │GraphQL  │ │JWT_Tool │ │ wfuzz   │ │ Newman  │ │Scout/DBn│     │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘     │
└───────────────────────────────────────────────────────────────────┘
```

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [API Reference](http://localhost/docs) (when running)

## Project Structure

```
noovastack-vapt/
├── backend/              # FastAPI application
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Configuration, security
│   │   ├── models/       # SQLAlchemy models
│   │   └── schemas/      # Pydantic schemas
│   └── requirements.txt
├── frontend/             # React application
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── pages/        # Page components
│   │   ├── services/     # API services
│   │   └── stores/       # State management
│   └── package.json
├── orchestrator/         # Celery task queue
│   └── tasks.py
├── configs/              # Configuration files
│   ├── nginx/
│   ├── openvas/
│   └── zap/
├── migrations/           # Database migrations
├── docs/                 # Documentation
├── docker-compose.yml    # Container orchestration
└── .env.example          # Environment template
```

## Scanner Tools (21 Integrated)

### Network & Vulnerability Scanning
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Nmap** | Port scanning, service detection | Default scan profiles |
| **OpenVAS** | Comprehensive vulnerability scanning | Full and fast configs |
| **Nuclei** | Template-based vulnerability detection | 8000+ templates |

### Web Application Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **OWASP ZAP** | Web application security testing | Active/passive scans |
| **Nikto** | Web server scanning | Default configuration |
| **SQLmap** | SQL injection detection | Automated testing |

### Container Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Trivy** | Container image vulnerability scanner | CRITICAL/HIGH/MEDIUM |
| **Docker Bench** | Docker CIS benchmark audit | Security best practices |
| **Clair** | Static container vulnerability analysis | Combo mode |
| **Falco** | Container runtime security monitoring | Default rules |

### Cloud Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **ScoutSuite** | Multi-cloud security audit (AWS/Azure/GCP) | Full assessment |
| **Prowler** | AWS security assessment | CIS benchmarks |

### Infrastructure as Code (IaC) Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Checkov** | IaC scanning (Terraform/CloudFormation/K8s) | All policies |
| **Terrascan** | IaC policy enforcement | OPA policies |

### Kubernetes Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Kube-hunter** | Kubernetes penetration testing | Remote/internal modes |
| **Kube-bench** | CIS Kubernetes benchmark | Node compliance |

### API Security
| Tool | Purpose | Configuration |
|------|---------|---------------|
| **Arjun** | HTTP parameter discovery | Stable mode |
| **GraphQLmap** | GraphQL security testing | Introspection/injection |
| **JWT_Tool** | JWT token analysis & attacks | Safe mode (no exploits) |
| **wfuzz** | API endpoint fuzzing | Custom wordlists |
| **Newman** | Postman API collection testing | Security test suites |

## Scan Types

| Scan Type | Tools Used | Duration |
|-----------|------------|----------|
| **Quick Scan** | Nmap, Nuclei | 5-15 min |
| **Full Scan** | All network/web tools | 30-60 min |
| **Web Application** | Nuclei, ZAP, Nikto, SQLmap | 20-45 min |
| **Container Security** | Trivy, Docker Bench, Clair, Falco | 15-30 min |
| **Cloud Security** | ScoutSuite, Prowler | 30-60 min |
| **IaC Security** | Checkov, Terrascan | 10-20 min |
| **Kubernetes** | Kube-hunter, Kube-bench | 15-30 min |
| **API Security** | Arjun, GraphQLmap, JWT_Tool, wfuzz, Newman | 15-30 min |
| **Custom** | User-selected tools | Varies |

## API Endpoints

### Scans
- `POST /api/v1/scans` - Create new scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/{id}` - Get scan details
- `GET /api/v1/scans/{id}/findings` - Get scan findings
- `POST /api/v1/scans/{id}/cancel` - Cancel scan

### Reports
- `GET /api/v1/reports` - List reports
- `POST /api/v1/reports/generate/{scan_id}` - Generate report
- `GET /api/v1/reports/{id}/download` - Download report

### Dashboard
- `GET /api/v1/dashboard/stats` - Get statistics

## Development

### Local Development
```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

### Running Tests
```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
npm test
```

## Production Deployment

See [Deployment Guide](docs/DEPLOYMENT.md) for:
- VM requirements
- SSL/TLS configuration
- Security hardening
- Backup procedures
- Monitoring setup

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Security: security@your-org.com
