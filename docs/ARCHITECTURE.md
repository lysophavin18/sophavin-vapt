# Noovastack-VAPT Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           NOOVASTACK-VAPT PLATFORM                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────────────┐ │
│  │   NGINX      │────▶│   FRONTEND   │     │         ISOLATED SCAN NETWORK    │ │
│  │   Reverse    │     │   (React)    │     │  ┌────────┐  ┌────────┐          │ │
│  │   Proxy      │     │   :3000      │     │  │OpenVAS │  │  ZAP   │          │ │
│  │   :80/:443   │     └──────────────┘     │  │ :9392  │  │ :8080  │          │ │
│  └──────┬───────┘                          │  └────────┘  └────────┘          │ │
│         │                                  │  ┌────────┐  ┌────────┐          │ │
│         ▼                                  │  │ Nuclei │  │ Nikto  │          │ │
│  ┌──────────────┐     ┌──────────────┐     │  │        │  │        │          │ │
│  │   BACKEND    │────▶│    REDIS     │     │  └────────┘  └────────┘          │ │
│  │   (FastAPI)  │     │    Queue     │     │  ┌────────┐  ┌────────┐          │ │
│  │   :8000      │     │    :6379     │     │  │ SQLmap │  │  Nmap  │          │ │
│  └──────┬───────┘     └──────┬───────┘     │  │        │  │        │          │ │
│         │                    │             │  └────────┘  └────────┘          │ │
│         ▼                    ▼             └──────────────────────────────────┘ │
│  ┌──────────────┐     ┌──────────────┐                    ▲                     │
│  │  PostgreSQL  │     │ ORCHESTRATOR │────────────────────┘                     │
│  │    :5432     │◀────│   (Celery)   │                                          │
│  │              │     │   Workers    │                                          │
│  └──────────────┘     └──────────────┘                                          │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Service Responsibilities

### 1. Frontend UI (React + TypeScript)
- **Port**: 3000
- **Responsibilities**:
  - User authentication (login/logout)
  - Dashboard with scan metrics and charts
  - Single target scan form with validation
  - Real-time scan progress monitoring
  - Scan history and results viewer
  - PDF report download
  - Admin panel for user management

### 2. Backend API (FastAPI + Python)
- **Port**: 8000
- **Responsibilities**:
  - REST API endpoints
  - JWT authentication & authorization
  - Target validation (IP/domain/URL format)
  - Rate limiting (10 scans/hour per user)
  - Scan job submission to queue
  - Result aggregation and normalization
  - PDF report generation
  - Audit logging

### 3. Scan Orchestrator (Celery Workers)
- **Responsibilities**:
  - Consume scan jobs from Redis queue
  - System resource checking (CPU/RAM)
  - Sequential tool execution pipeline
  - Progress reporting
  - Error handling and retries
  - Result collection and parsing

### 4. Redis (Message Broker + Cache)
- **Port**: 6379
- **Responsibilities**:
  - Task queue for Celery
  - Scan progress caching
  - Rate limiting state
  - Session storage

### 5. PostgreSQL Database
- **Port**: 5432
- **Responsibilities**:
  - User accounts and roles
  - Scan configurations
  - Scan results and findings
  - Audit logs
  - Target approvals

### 6. Security Scanners

| Scanner | Purpose | Port | Constraints |
|---------|---------|------|-------------|
| **OpenVAS/Greenbone** | Network vulnerability scanning | 9392 | Max 1 concurrent scan, 1 host |
| **Nmap** | Port & service discovery | - | First in pipeline |
| **Nuclei** | Template-based vuln scanning | - | Safe templates only |
| **OWASP ZAP** | Web/API scanning (headless) | 8080 | Spider depth limited |
| **Nikto** | Web server scanning | - | Non-aggressive |
| **SQLmap** | SQL injection detection | - | --level=1 --risk=1 |

## Scan Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SCAN EXECUTION FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

  User Input                  Validation                    Queue
     │                            │                           │
     ▼                            ▼                           ▼
┌─────────┐    ┌─────────────────────────────┐    ┌───────────────────┐
│ Submit  │───▶│ 1. Validate target format   │───▶│ Add to Redis      │
│ Target  │    │ 2. Check if external        │    │ Queue             │
│         │    │ 3. Require approval if ext  │    │                   │
└─────────┘    │ 4. Check rate limits        │    └─────────┬─────────┘
               └─────────────────────────────┘              │
                                                            ▼
                                              ┌───────────────────────┐
                                              │ ORCHESTRATOR PICKS UP │
                                              │ ──────────────────────│
                                              │ 1. Check CPU < 80%    │
                                              │ 2. Check RAM < 85%    │
                                              │ 3. If busy → requeue  │
                                              └───────────┬───────────┘
                                                          │
                            ┌─────────────────────────────┼─────────────────────────────┐
                            ▼                             ▼                             ▼
                   ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
                   │   PHASE 1:      │         │   PHASE 2:      │         │   PHASE 3:      │
                   │   DISCOVERY     │         │   VULN SCAN     │         │   WEB SCAN      │
                   │─────────────────│         │─────────────────│         │─────────────────│
                   │ • Nmap          │────────▶│ • OpenVAS       │────────▶│ • ZAP           │
                   │   -sV -sC       │  ports  │   Full & Fast   │  http   │ • Nikto         │
                   │   --top-ports   │         │ • Nuclei        │  ports  │ • SQLmap        │
                   │   1000          │         │   safe-only     │         │   (if forms)    │
                   └─────────────────┘         └─────────────────┘         └─────────────────┘
                                                                                    │
                                                                                    ▼
                                              ┌───────────────────────────────────────────┐
                                              │              RESULT AGGREGATION           │
                                              │ ───────────────────────────────────────── │
                                              │ 1. Parse all tool outputs                 │
                                              │ 2. Normalize to CVE/CVSS format           │
                                              │ 3. Deduplicate findings                   │
                                              │ 4. Calculate severity counts              │
                                              │ 5. Store in PostgreSQL                    │
                                              │ 6. Generate PDF report                    │
                                              └───────────────────────────────────────────┘
```

## Network Isolation

```
┌─────────────────────────────────────────────────────────────────┐
│                    DOCKER NETWORKS                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ FRONTEND NETWORK (noovastack-frontend)                      ││
│  │ ┌────────┐  ┌────────┐  ┌────────┐                          ││
│  │ │ nginx  │  │frontend│  │backend │                          ││
│  │ └────────┘  └────────┘  └────────┘                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                           │                                      │
│                           │ (backend only)                       │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ BACKEND NETWORK (noovastack-backend)                        ││
│  │ ┌────────┐  ┌────────┐  ┌────────────┐                      ││
│  │ │backend │  │ redis  │  │ postgresql │                      ││
│  │ └────────┘  └────────┘  └────────────┘                      ││
│  │ ┌────────────┐                                              ││
│  │ │orchestrator│                                              ││
│  │ └────────────┘                                              ││
│  └─────────────────────────────────────────────────────────────┘│
│                           │                                      │
│                           │ (orchestrator only)                  │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ SCANNER NETWORK (noovastack-scanners) - ISOLATED            ││
│  │ ┌────────────┐  ┌────────┐  ┌────────┐  ┌────────┐          ││
│  │ │orchestrator│  │openvas │  │  zap   │  │ nuclei │          ││
│  │ └────────────┘  └────────┘  └────────┘  └────────┘          ││
│  │ ┌────────┐  ┌────────┐  ┌────────┐                          ││
│  │ │ nikto  │  │ sqlmap │  │  nmap  │                          ││
│  │ └────────┘  └────────┘  └────────┘                          ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **User submits scan** → Frontend validates input → Backend API
2. **Backend validates** → Checks auth, rate limits, target format
3. **Job queued** → Redis queue stores scan task
4. **Orchestrator picks up** → Checks system resources
5. **Tools execute sequentially** → Nmap → OpenVAS/Nuclei → Web scanners
6. **Results collected** → Parsed and normalized
7. **Stored in PostgreSQL** → Findings, CVEs, severity
8. **Report generated** → PDF with executive summary
9. **User notified** → Dashboard updates, download available

## Security Controls

| Control | Implementation |
|---------|----------------|
| Authentication | JWT tokens, bcrypt password hashing |
| Authorization | Role-based (admin/user) |
| Rate Limiting | 10 scans/hour/user, Redis-backed |
| Input Validation | Strict regex for IP/domain/URL |
| External Approval | Admin must approve external targets |
| Audit Logging | Every action logged with timestamp/user |
| Network Isolation | Separate Docker networks |
| Safe Defaults | No auto-exploitation, conservative tool settings |
