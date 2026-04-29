import React from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Chip,
  LinearProgress,
  IconButton,
  Button,
  Stack,
} from '@mui/material';
import {
  Security as SecurityIcon,
  BugReport as BugIcon,
  Speed as SpeedIcon,
  History as HistoryIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  PlayArrow as PlayIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from 'recharts';
import { format } from 'date-fns';
import { api } from '../services/api';

// Severity colors
const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
};

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  subtitle?: string;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color, subtitle }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent>
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
        <Box>
          <Typography color="text.secondary" variant="body2" gutterBottom>
            {title}
          </Typography>
          <Typography variant="h4" fontWeight="bold">
            {value}
          </Typography>
          {subtitle && (
            <Typography variant="caption" color="text.secondary">
              {subtitle}
            </Typography>
          )}
        </Box>
        <Box
          sx={{
            p: 1,
            borderRadius: 2,
            bgcolor: `${color}20`,
            color: color,
          }}
        >
          {icon}
        </Box>
      </Stack>
    </CardContent>
  </Card>
);

interface ScanItemProps {
  scan: {
    scan_id: string;
    target_value: string;
    status: string;
    progress: number;
    total_findings: number;
    critical_count: number;
    high_count: number;
    created_at: string;
  };
}

const ScanStatusChip: React.FC<{ status: string }> = ({ status }) => {
  const statusConfig: Record<string, { color: 'success' | 'warning' | 'error' | 'info' | 'default'; label: string }> = {
    completed: { color: 'success', label: 'Completed' },
    running: { color: 'info', label: 'Running' },
    queued: { color: 'warning', label: 'Queued' },
    pending: { color: 'default', label: 'Pending' },
    failed: { color: 'error', label: 'Failed' },
    cancelled: { color: 'default', label: 'Cancelled' },
  };

  const config = statusConfig[status] || statusConfig.pending;

  return <Chip size="small" label={config.label} color={config.color} />;
};

const RecentScanItem: React.FC<ScanItemProps> = ({ scan }) => {
  const navigate = useNavigate();

  return (
    <Card
      sx={{
        mb: 1,
        cursor: 'pointer',
        '&:hover': { bgcolor: 'action.hover' },
      }}
      onClick={() => navigate(`/scan/${scan.scan_id}`)}
    >
      <CardContent sx={{ py: 1.5, '&:last-child': { pb: 1.5 } }}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="body1" fontWeight="medium">
              {scan.target_value}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {format(new Date(scan.created_at), 'MMM d, yyyy HH:mm')}
            </Typography>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center">
            {scan.status === 'running' && (
              <Box sx={{ width: 100 }}>
                <LinearProgress variant="determinate" value={scan.progress} />
              </Box>
            )}
            <ScanStatusChip status={scan.status} />
            {scan.critical_count > 0 && (
              <Chip
                size="small"
                label={`${scan.critical_count} Critical`}
                sx={{ bgcolor: SEVERITY_COLORS.critical, color: 'white' }}
              />
            )}
          </Stack>
        </Stack>
      </CardContent>
    </Card>
  );
};

const DashboardPage: React.FC = () => {
  const navigate = useNavigate();

  // Fetch dashboard stats
  const { data: stats, isLoading, refetch } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => api.get('/api/v1/dashboard/stats').then((res) => res.data),
    refetchInterval: (data: any) => {
      // Poll every 5 s when there are active scans, otherwise every 30 s
      const activeScans = data?.active_scans ?? 0;
      return activeScans > 0 ? 5000 : 30000;
    },
  });

  // Severity distribution data for pie chart
  const severityData = stats
    ? [
        { name: 'Critical', value: stats.critical_findings, color: SEVERITY_COLORS.critical },
        { name: 'High', value: stats.high_findings, color: SEVERITY_COLORS.high },
        { name: 'Medium', value: stats.medium_findings, color: SEVERITY_COLORS.medium },
        { name: 'Low', value: stats.low_findings, color: SEVERITY_COLORS.low },
        { name: 'Info', value: stats.info_findings, color: SEVERITY_COLORS.info },
      ].filter((d) => d.value > 0)
    : [];

  if (isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Dashboard
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Vulnerability Assessment Overview
          </Typography>
        </Box>
        <Stack direction="row" spacing={2}>
          <IconButton onClick={() => refetch()}>
            <RefreshIcon />
          </IconButton>
          <Button
            variant="contained"
            startIcon={<PlayIcon />}
            onClick={() => navigate('/scan')}
          >
            New Scan
          </Button>
        </Stack>
      </Stack>

      {/* Stats Cards */}
      <Grid container spacing={3} mb={3}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Scans"
            value={stats?.total_scans || 0}
            icon={<SecurityIcon />}
            color="#6366f1"
            subtitle={`${stats?.scans_today || 0} today`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Active Scans"
            value={stats?.active_scans || 0}
            icon={<SpeedIcon />}
            color="#22c55e"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="Total Findings"
            value={stats?.total_findings || 0}
            icon={<BugIcon />}
            color="#f59e0b"
            subtitle={`${stats?.critical_findings || 0} critical`}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title="This Week"
            value={stats?.scans_this_week || 0}
            icon={<HistoryIcon />}
            color="#3b82f6"
            subtitle="scans completed"
          />
        </Grid>
      </Grid>

      {/* Charts and Recent Scans */}
      <Grid container spacing={3}>
        {/* Severity Distribution */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: 400 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Severity Distribution
              </Typography>
              {severityData.length > 0 ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={2}
                      dataKey="value"
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <Box
                  sx={{
                    height: 300,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  <Typography color="text.secondary">No findings yet</Typography>
                </Box>
              )}
              {/* Legend */}
              <Stack direction="row" spacing={2} justifyContent="center" flexWrap="wrap">
                {severityData.map((item) => (
                  <Stack key={item.name} direction="row" spacing={0.5} alignItems="center">
                    <Box
                      sx={{
                        width: 12,
                        height: 12,
                        borderRadius: '50%',
                        bgcolor: item.color,
                      }}
                    />
                    <Typography variant="caption">
                      {item.name}: {item.value}
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Scans */}
        <Grid item xs={12} md={8}>
          <Card sx={{ height: 400 }}>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">Recent Scans</Typography>
                <Button size="small" onClick={() => navigate('/history')}>
                  View All
                </Button>
              </Stack>
              <Box sx={{ maxHeight: 320, overflow: 'auto' }}>
                {stats?.recent_scans?.length > 0 ? (
                  stats.recent_scans.map((scan: any) => (
                    <RecentScanItem key={scan.scan_id} scan={scan} />
                  ))
                ) : (
                  <Box
                    sx={{
                      height: 280,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexDirection: 'column',
                    }}
                  >
                    <SecurityIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                    <Typography color="text.secondary">No scans yet</Typography>
                    <Button
                      variant="outlined"
                      startIcon={<PlayIcon />}
                      onClick={() => navigate('/scan')}
                      sx={{ mt: 2 }}
                    >
                      Start First Scan
                    </Button>
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* System Status */}
      <Grid container spacing={3} mt={1}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                Scanner Status (26 Tools)
              </Typography>
              <Grid container spacing={2}>
                {[
                  // Network & Vulnerability
                  { name: 'OpenVAS', status: 'online', color: 'success' },
                  { name: 'Nuclei', status: 'online', color: 'success' },
                  { name: 'Nmap', status: 'online', color: 'success' },
                  // Web Application
                  { name: 'OWASP ZAP', status: 'online', color: 'success' },
                  { name: 'Nikto', status: 'online', color: 'success' },
                  { name: 'SQLmap', status: 'online', color: 'success' },
                  // Dynamic Web Scanning
                  { name: 'Wapiti', status: 'online', color: 'success' },
                  { name: 'Dalfox', status: 'online', color: 'success' },
                  { name: 'Feroxbuster', status: 'online', color: 'success' },
                  { name: 'Commix', status: 'online', color: 'success' },
                  { name: 'CMSeeK', status: 'online', color: 'success' },
                  { name: 'Sn1per', status: 'online', color: 'success' },
                  // Container Security
                  { name: 'Docker Bench', status: 'online', color: 'success' },
                  { name: 'Clair', status: 'online', color: 'success' },
                  { name: 'Falco', status: 'online', color: 'success' },
                  // Cloud Security
                  { name: 'ScoutSuite', status: 'online', color: 'success' },
                  { name: 'Prowler', status: 'online', color: 'success' },
                  // IaC Security
                  { name: 'Checkov', status: 'online', color: 'success' },
                  { name: 'Terrascan', status: 'online', color: 'success' },
                  // Kubernetes Security
                  { name: 'Kube-hunter', status: 'online', color: 'success' },
                  { name: 'Kube-bench', status: 'online', color: 'success' },
                  // API Security
                  { name: 'Arjun', status: 'online', color: 'success' },
                  { name: 'GraphQLmap', status: 'online', color: 'success' },
                  { name: 'JWT_Tool', status: 'online', color: 'success' },
                  { name: 'wfuzz', status: 'online', color: 'success' },
                  { name: 'Newman', status: 'online', color: 'success' },
                ].map((scanner) => (
                  <Grid item xs={6} sm={4} md={2} key={scanner.name}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Box
                        sx={{
                          width: 8,
                          height: 8,
                          borderRadius: '50%',
                          bgcolor:
                            scanner.status === 'online' ? 'success.main' : 'error.main',
                        }}
                      />
                      <Typography variant="body2">{scanner.name}</Typography>
                    </Stack>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default DashboardPage;
