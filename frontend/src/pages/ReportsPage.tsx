import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  Button,
  Grid,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  LinearProgress,
  Alert,
} from '@mui/material';
import {
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Description as ReportIcon,
  PictureAsPdf as PdfIcon,
  Code as JsonIcon,
  Html as HtmlIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { reportsApi, scansApi } from '../services/api';

const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const FormatIcon: React.FC<{ format: string }> = ({ format }) => {
  switch (format) {
    case 'pdf':
      return <PdfIcon color="error" />;
    case 'json':
      return <JsonIcon color="warning" />;
    case 'html':
      return <HtmlIcon color="info" />;
    default:
      return <ReportIcon />;
  }
};

const ReportsPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [generateDialogOpen, setGenerateDialogOpen] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [reportFormat, setReportFormat] = useState<'pdf' | 'html' | 'json'>('pdf');

  // Fetch reports
  const { data: reports, isLoading, refetch } = useQuery({
    queryKey: ['reports'],
    queryFn: () => reportsApi.list(),
  });

  // Fetch completed scans for dropdown
  const { data: scans } = useQuery({
    queryKey: ['completed-scans'],
    queryFn: () => scansApi.list({ status: 'completed', per_page: 50 }),
  });

  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: () => reportsApi.generate(selectedScanId, reportFormat),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] });
      setGenerateDialogOpen(false);
      setSelectedScanId('');
    },
  });

  // Download handler
  const handleDownload = async (reportId: string, filename: string) => {
    try {
      const blob = await reportsApi.download(reportId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error('Download failed:', error);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Reports
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Generate and download vulnerability assessment reports
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <IconButton onClick={() => refetch()}>
            <RefreshIcon />
          </IconButton>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setGenerateDialogOpen(true)}
          >
            Generate Report
          </Button>
        </Stack>
      </Stack>

      {/* Report Format Cards */}
      <Grid container spacing={2} mb={3}>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center">
                <PdfIcon sx={{ fontSize: 40 }} color="error" />
                <Box>
                  <Typography variant="h6">PDF Reports</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Formatted for stakeholder review
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center">
                <HtmlIcon sx={{ fontSize: 40 }} color="info" />
                <Box>
                  <Typography variant="h6">HTML Reports</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Interactive web-based reports
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={4}>
          <Card>
            <CardContent>
              <Stack direction="row" spacing={2} alignItems="center">
                <JsonIcon sx={{ fontSize: 40 }} color="warning" />
                <Box>
                  <Typography variant="h6">JSON Reports</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Machine-readable for integrations
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Reports Table */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Generated Reports
          </Typography>
          {isLoading ? (
            <LinearProgress />
          ) : reports?.items?.length > 0 ? (
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Report</TableCell>
                    <TableCell>Target</TableCell>
                    <TableCell>Format</TableCell>
                    <TableCell>Size</TableCell>
                    <TableCell>Generated</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {reports.items.map((report: any) => (
                    <TableRow key={report.id}>
                      <TableCell>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <FormatIcon format={report.format} />
                          <Typography variant="body2" fontWeight="medium">
                            {report.filename}
                          </Typography>
                        </Stack>
                      </TableCell>
                      <TableCell>{report.target_value}</TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          label={report.format.toUpperCase()}
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>{formatBytes(report.file_size)}</TableCell>
                      <TableCell>
                        {format(new Date(report.created_at), 'MMM d, yyyy HH:mm')}
                      </TableCell>
                      <TableCell align="right">
                        <IconButton
                          size="small"
                          onClick={() => handleDownload(report.id, report.filename)}
                        >
                          <DownloadIcon />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          ) : (
            <Box sx={{ py: 4, textAlign: 'center' }}>
              <ReportIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
              <Typography color="text.secondary">
                No reports generated yet
              </Typography>
              <Button
                variant="outlined"
                startIcon={<AddIcon />}
                onClick={() => setGenerateDialogOpen(true)}
                sx={{ mt: 2 }}
              >
                Generate Your First Report
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Generate Report Dialog */}
      <Dialog
        open={generateDialogOpen}
        onClose={() => setGenerateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Generate Report</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 1 }}>
            <FormControl fullWidth>
              <InputLabel>Select Scan</InputLabel>
              <Select
                value={selectedScanId}
                label="Select Scan"
                onChange={(e) => setSelectedScanId(e.target.value)}
              >
                {scans?.items?.map((scan: any) => (
                  <MenuItem key={scan.scan_id} value={scan.scan_id}>
                    <Stack>
                      <Typography variant="body2">{scan.target_value}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {format(new Date(scan.created_at), 'MMM d, yyyy')} • 
                        {scan.total_findings} findings
                      </Typography>
                    </Stack>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl fullWidth>
              <InputLabel>Report Format</InputLabel>
              <Select
                value={reportFormat}
                label="Report Format"
                onChange={(e) => setReportFormat(e.target.value as any)}
              >
                <MenuItem value="pdf">
                  <Stack direction="row" spacing={1} alignItems="center">
                    <PdfIcon fontSize="small" color="error" />
                    <Typography>PDF - Professional Report</Typography>
                  </Stack>
                </MenuItem>
                <MenuItem value="html">
                  <Stack direction="row" spacing={1} alignItems="center">
                    <HtmlIcon fontSize="small" color="info" />
                    <Typography>HTML - Interactive Report</Typography>
                  </Stack>
                </MenuItem>
                <MenuItem value="json">
                  <Stack direction="row" spacing={1} alignItems="center">
                    <JsonIcon fontSize="small" color="warning" />
                    <Typography>JSON - Machine Readable</Typography>
                  </Stack>
                </MenuItem>
              </Select>
            </FormControl>

            {generateMutation.isError && (
              <Alert severity="error">
                Failed to generate report. Please try again.
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setGenerateDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={() => generateMutation.mutate()}
            disabled={!selectedScanId || generateMutation.isPending}
          >
            {generateMutation.isPending ? 'Generating...' : 'Generate'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ReportsPage;
