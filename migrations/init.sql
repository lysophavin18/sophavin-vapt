-- ============================================================================
-- KOU PREY SECURITY DATABASE SCHEMA
-- PostgreSQL 16+
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- ENUM TYPES
-- ============================================================================
CREATE TYPE user_role AS ENUM ('admin', 'user');
CREATE TYPE scan_status AS ENUM ('pending', 'queued', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE scan_type AS ENUM ('full', 'quick', 'web_only', 'network_only');
CREATE TYPE target_type AS ENUM ('ip', 'domain', 'url');
CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected');

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(100) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    full_name VARCHAR(255),
    organization VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE,
    last_login TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);

-- ============================================================================
-- TARGETS TABLE
-- ============================================================================
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    value VARCHAR(500) NOT NULL,
    target_type target_type NOT NULL,
    is_external BOOLEAN NOT NULL DEFAULT FALSE,
    approval_status approval_status NOT NULL DEFAULT 'pending',
    approved_by INTEGER REFERENCES users(id),
    approved_at TIMESTAMP WITH TIME ZONE,
    organization VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_targets_value ON targets(value);
CREATE INDEX idx_targets_approval ON targets(approval_status);

-- ============================================================================
-- SCANS TABLE
-- ============================================================================
CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(36) NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    target_id INTEGER NOT NULL REFERENCES targets(id),
    scan_type scan_type NOT NULL DEFAULT 'full',
    status scan_status NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 5 CHECK (priority >= 1 AND priority <= 10),
    progress INTEGER NOT NULL DEFAULT 0 CHECK (progress >= 0 AND progress <= 100),
    current_phase VARCHAR(100),
    scheduled_at TIMESTAMP WITH TIME ZONE,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,
    report_path VARCHAR(500),
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_scans_scan_id ON scans(scan_id);
CREATE INDEX idx_scans_user_status ON scans(user_id, status);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- ============================================================================
-- FINDINGS TABLE
-- ============================================================================
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity NOT NULL,
    cve_id VARCHAR(50),
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(100),
    affected_component VARCHAR(255),
    affected_port INTEGER,
    affected_service VARCHAR(100),
    affected_url VARCHAR(1000),
    evidence TEXT,
    request TEXT,
    response TEXT,
    solution TEXT,
    references JSONB,
    tool_name VARCHAR(50),
    raw_output TEXT,
    fingerprint VARCHAR(64),
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_cve ON findings(cve_id);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);

-- ============================================================================
-- TOOL RESULTS TABLE
-- ============================================================================
CREATE TABLE tool_results (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool_name VARCHAR(50) NOT NULL,
    status VARCHAR(20),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    raw_output TEXT,
    parsed_output JSONB,
    findings_count INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    exit_code INTEGER
);

CREATE INDEX idx_tool_results_scan ON tool_results(scan_id);
CREATE INDEX idx_tool_results_tool ON tool_results(tool_name);

-- ============================================================================
-- AUDIT LOGS TABLE
-- ============================================================================
CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    request_method VARCHAR(10),
    request_path VARCHAR(500),
    details JSONB,
    status VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);

-- ============================================================================
-- SYSTEM SETTINGS TABLE
-- ============================================================================
CREATE TABLE system_settings (
    id SERIAL PRIMARY KEY,
    key VARCHAR(100) NOT NULL UNIQUE,
    value TEXT,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE,
    updated_by INTEGER REFERENCES users(id)
);

CREATE INDEX idx_settings_key ON system_settings(key);

-- ============================================================================
-- SESSIONS TABLE (for token management)
-- ============================================================================
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    user_agent VARCHAR(500),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_sessions_token ON user_sessions(token_hash);
CREATE INDEX idx_sessions_expires ON user_sessions(expires_at);

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Create default admin user (password: 'admin123' - CHANGE IN PRODUCTION!)
INSERT INTO users (email, username, hashed_password, role, is_active, is_verified, full_name)
VALUES (
    'admin@kouprey.local',
    'admin',
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4Iu2T3XF.Z1rVsEO',  -- bcrypt hash of 'admin123'
    'admin',
    TRUE,
    TRUE,
    'System Administrator'
);

-- Default system settings
INSERT INTO system_settings (key, value, description) VALUES
    ('max_concurrent_scans', '1', 'Maximum number of concurrent scans'),
    ('openvas_max_hosts', '1', 'Maximum hosts per OpenVAS scan'),
    ('scan_timeout_seconds', '7200', 'Default scan timeout in seconds'),
    ('rate_limit_scans_per_hour', '10', 'Max scans per user per hour'),
    ('require_external_approval', 'true', 'Require admin approval for external targets'),
    ('feed_update_schedule', '0 2 * * *', 'Cron schedule for vulnerability feed updates');

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_settings_updated_at
    BEFORE UPDATE ON system_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- VIEWS
-- ============================================================================

-- Dashboard summary view
CREATE VIEW dashboard_summary AS
SELECT
    COUNT(*) FILTER (WHERE status = 'completed') as completed_scans,
    COUNT(*) FILTER (WHERE status = 'running') as active_scans,
    COUNT(*) FILTER (WHERE status = 'failed') as failed_scans,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE) as scans_today,
    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as scans_this_week,
    SUM(critical_count) as total_critical,
    SUM(high_count) as total_high,
    SUM(medium_count) as total_medium,
    SUM(low_count) as total_low,
    SUM(total_findings) as total_findings
FROM scans;

-- User scan statistics view
CREATE VIEW user_scan_stats AS
SELECT
    u.id as user_id,
    u.username,
    COUNT(s.id) as total_scans,
    COUNT(*) FILTER (WHERE s.status = 'completed') as completed_scans,
    SUM(s.total_findings) as total_findings,
    SUM(s.critical_count) as critical_findings,
    MAX(s.created_at) as last_scan_at
FROM users u
LEFT JOIN scans s ON u.id = s.user_id
GROUP BY u.id, u.username;

-- ============================================================================
-- COMMENTS
-- ============================================================================
COMMENT ON TABLE users IS 'User accounts for the VAPT platform';
COMMENT ON TABLE targets IS 'Scan targets (IP addresses, domains, URLs)';
COMMENT ON TABLE scans IS 'Vulnerability scans executed in the platform';
COMMENT ON TABLE findings IS 'Vulnerabilities discovered during scans';
COMMENT ON TABLE tool_results IS 'Raw results from individual scanning tools';
COMMENT ON TABLE audit_logs IS 'Security audit trail for all actions';
COMMENT ON TABLE system_settings IS 'Platform configuration settings';
