import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  Chip,
  LinearProgress,
  Button,
  Grid,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Tooltip,
  Tab,
  Tabs,
  Alert,
  Collapse,
} from '@mui/material';
import {
  ArrowBack as BackIcon,
  Refresh as RefreshIcon,
  Stop as StopIcon,
  Download as DownloadIcon,
  BugReport as BugIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { scansApi, reportsApi } from '../services/api';

// Severity colors
const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <Box hidden={value !== index} sx={{ pt: 2 }}>
    {value === index && children}
  </Box>
);

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <Chip
    size="small"
    label={severity.toUpperCase()}
    sx={{
      bgcolor: SEVERITY_COLORS[severity] || SEVERITY_COLORS.info,
      color: 'white',
      fontWeight: 'bold',
    }}
  />
);

const StatusChip: React.FC<{ status: string }> = ({ status }) => {
  const statusConfig: Record<string, { color: 'success' | 'warning' | 'error' | 'info' | 'default'; icon: React.ReactNode }> = {
    completed: { color: 'success', icon: <CheckIcon fontSize="small" /> },
    running: { color: 'info', icon: <ScheduleIcon fontSize="small" /> },
    queued: { color: 'warning', icon: <ScheduleIcon fontSize="small" /> },
    pending: { color: 'default', icon: <ScheduleIcon fontSize="small" /> },
    failed: { color: 'error', icon: <ErrorIcon fontSize="small" /> },
    cancelled: { color: 'default', icon: <StopIcon fontSize="small" /> },
  };

  const config = statusConfig[status] || statusConfig.pending;

  return (
    <Chip
      size="small"
      label={status.charAt(0).toUpperCase() + status.slice(1)}
      color={config.color as any}
      icon={config.icon as React.ReactElement}
    />
  );
};

const FindingRow: React.FC<{ finding: any }> = ({ finding }) => {
  const [expanded, setExpanded] = React.useState(false);

  return (
    <>
      <TableRow
        sx={{
          cursor: 'pointer',
          '&:hover': { bgcolor: 'action.hover' },
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <TableCell>
          <IconButton size="small">
            {expanded ? <CollapseIcon /> : <ExpandIcon />}
          </IconButton>
        </TableCell>
        <TableCell>
          <SeverityBadge severity={finding.severity} />
        </TableCell>
        <TableCell>
          <Typography variant="body2" fontWeight="medium">
            {finding.title}
          </Typography>
        </TableCell>
        <TableCell>{finding.cve_id || '-'}</TableCell>
        <TableCell>
          <Chip size="small" label={finding.tool_name} variant="outlined" />
        </TableCell>
        <TableCell>{finding.affected_component || '-'}</TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={6} sx={{ py: 0, borderBottom: expanded ? 1 : 0 }}>
          <Collapse in={expanded}>
            <Box sx={{ p: 2, bgcolor: 'background.default', borderRadius: 1, my: 1 }}>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    Description
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {finding.description || 'No description available'}
                  </Typography>
                </Grid>
                {finding.remediation && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" gutterBottom>
                      Remediation
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {finding.remediation}
                    </Typography>
                  </Grid>
                )}
                {finding.evidence && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" gutterBottom>
                      Evidence
                    </Typography>
                    <Paper
                      sx={{
                        p: 1,
                        bgcolor: '#1e1e1e',
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                        overflow: 'auto',
                        maxHeight: 200,
                      }}
                    >
                      <pre style={{ margin: 0 }}>{finding.evidence}</pre>
                    </Paper>
                  </Grid>
                )}
                {finding.references && finding.references.length > 0 && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle2" gutterBottom>
                      References
                    </Typography>
                    <Stack spacing={0.5}>
                      {finding.references.map((ref: string, i: number) => (
                        <Typography
                          key={i}
                          variant="body2"
                          component="a"
                          href={ref}
                          target="_blank"
                          rel="noopener"
                          color="primary"
                        >
                          {ref}
                        </Typography>
                      ))}
                    </Stack>
                  </Grid>
                )}
              </Grid>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
};

const ScanDetailsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [tabValue, setTabValue] = React.useState(0);

  // Fetch scan details
  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => scansApi.get(scanId!),
    refetchInterval: (query) => {
      const data = query.state.data;
      // Stop polling when scan is completed/failed/cancelled
      if (data && ['completed', 'failed', 'cancelled'].includes(data.status)) {
        return false;
      }
      return 5000; // Poll every 5 seconds
    },
  });

  // Fetch findings
  const { data: findings } = useQuery({
    queryKey: ['scan-findings', scanId],
    queryFn: () => scansApi.getFindings(scanId!),
    enabled: !!scan && scan.status === 'completed',
  });

  // Cancel scan mutation
  const cancelMutation = useMutation({
    mutationFn: () => scansApi.cancel(scanId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] });
    },
  });

  // Generate report mutation
  const generateReportMutation = useMutation({
    mutationFn: () => reportsApi.generate(scanId!, 'pdf'),
    onSuccess: (data) => {
      // Download the report
      window.open(`/api/v1/reports/${data.report_id}/download`, '_blank');
    },
  });

  if (isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
      </Box>
    );
  }

  if (!scan) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Scan not found</Alert>
        <Button startIcon={<BackIcon />} onClick={() => navigate('/history')} sx={{ mt: 2 }}>
          Back to History
        </Button>
      </Box>
    );
  }

  const isActive = ['running', 'queued', 'pending'].includes(scan.status);

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="flex-start" mb={3}>
        <Box>
          <Button
            startIcon={<BackIcon />}
            onClick={() => navigate('/history')}
            sx={{ mb: 1 }}
          >
            Back to History
          </Button>
          <Typography variant="h4" fontWeight="bold">
            {scan.target_value}
          </Typography>
          <Stack direction="row" spacing={2} alignItems="center" mt={1}>
            <StatusChip status={scan.status} />
            <Typography variant="body2" color="text.secondary">
              Started: {format(new Date(scan.created_at), 'MMM d, yyyy HH:mm')}
            </Typography>
            {scan.completed_at && (
              <Typography variant="body2" color="text.secondary">
                Completed: {format(new Date(scan.completed_at), 'MMM d, yyyy HH:mm')}
              </Typography>
            )}
          </Stack>
        </Box>
        <Stack direction="row" spacing={1}>
          <Tooltip title="Refresh">
            <IconButton
              onClick={() => queryClient.invalidateQueries({ queryKey: ['scan', scanId] })}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          {isActive && (
            <Button
              variant="outlined"
              color="error"
              startIcon={<StopIcon />}
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
            >
              Cancel
            </Button>
          )}
          {scan.status === 'completed' && (
            <Button
              variant="contained"
              startIcon={<DownloadIcon />}
              onClick={() => generateReportMutation.mutate()}
              disabled={generateReportMutation.isPending}
            >
              Export Report
            </Button>
          )}
        </Stack>
      </Stack>

      {/* Progress */}
      {isActive && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Stack direction="row" justifyContent="space-between" alignItems="center" mb={1}>
              <Typography variant="body2" fontWeight="medium">
                Scan Progress
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {scan.progress || 0}%
              </Typography>
            </Stack>
            <LinearProgress
              variant="determinate"
              value={scan.progress || 0}
              sx={{ height: 8, borderRadius: 1 }}
            />
            {scan.current_tool && (
              <Typography variant="caption" color="text.secondary" mt={1}>
                Currently running: {scan.current_tool}
              </Typography>
            )}
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" fontWeight="bold" color="error.main">
                {scan.critical_count || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Critical
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" fontWeight="bold" color="warning.main">
                {scan.high_count || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                High
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" fontWeight="bold" color="info.main">
                {scan.medium_count || 0}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Medium
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h4" fontWeight="bold" color="success.main">
                {(scan.low_count || 0) + (scan.info_count || 0)}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Low/Info
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Tabs */}
      <Card>
        <Tabs
          value={tabValue}
          onChange={(_, newValue) => setTabValue(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}
        >
          <Tab label={`Findings (${findings?.total || 0})`} />
          <Tab label="Tool Results" />
          <Tab label="Scan Details" />
        </Tabs>

        <TabPanel value={tabValue} index={0}>
          {findings?.items?.length > 0 ? (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell width={50}></TableCell>
                    <TableCell width={100}>Severity</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell width={120}>CVE</TableCell>
                    <TableCell width={100}>Tool</TableCell>
                    <TableCell>Component</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {findings.items.map((finding: any) => (
                    <FindingRow key={finding.id} finding={finding} />
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Box sx={{ p: 4, textAlign: 'center' }}>
              <BugIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
              <Typography color="text.secondary">
                {isActive ? 'Findings will appear here as the scan progresses' : 'No findings detected'}
              </Typography>
            </Box>
          )}
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={2}>
              {scan.tool_results?.map((result: any) => (
                <Grid item xs={12} sm={6} md={4} key={result.tool_name}>
                  <Card variant="outlined">
                    <CardContent>
                      <Stack direction="row" justifyContent="space-between" alignItems="center">
                        <Typography variant="subtitle1" fontWeight="medium">
                          {result.tool_name}
                        </Typography>
                        <StatusChip status={result.status} />
                      </Stack>
                      <Typography variant="body2" color="text.secondary" mt={1}>
                        Findings: {result.findings_count || 0}
                      </Typography>
                      {result.duration && (
                        <Typography variant="caption" color="text.secondary">
                          Duration: {Math.round(result.duration / 1000)}s
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                </Grid>
              )) || (
                <Grid item xs={12}>
                  <Typography color="text.secondary" textAlign="center">
                    No tool results available yet
                  </Typography>
                </Grid>
              )}
            </Grid>
          </Box>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Box sx={{ p: 2 }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Scan ID
                </Typography>
                <Typography variant="body1" fontFamily="monospace">
                  {scan.scan_id}
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Scan Type
                </Typography>
                <Typography variant="body1">{scan.scan_type}</Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Target Type
                </Typography>
                <Typography variant="body1">{scan.target_type}</Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2" color="text.secondary">
                  Created By
                </Typography>
                <Typography variant="body1">{scan.created_by || 'System'}</Typography>
              </Grid>
              <Grid item xs={12}>
                <Typography variant="body2" color="text.secondary">
                  Tools Used
                </Typography>
                <Stack direction="row" spacing={1} mt={0.5} flexWrap="wrap">
                  {scan.tools?.map((tool: string) => (
                    <Chip key={tool} label={tool} size="small" sx={{ mb: 0.5 }} />
                  ))}
                </Stack>
              </Grid>
            </Grid>
          </Box>
        </TabPanel>
      </Card>
    </Box>
  );
};

export default ScanDetailsPage;
