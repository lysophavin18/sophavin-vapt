import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  TextField,
  InputAdornment,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  FormControl,
  InputLabel,
  Select,
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  MoreVert as MoreIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { scansApi, reportsApi } from '../services/api';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
  info: '#2563eb',
};

const StatusChip: React.FC<{ status: string }> = ({ status }) => {
  const statusConfig: Record<string, { color: 'success' | 'warning' | 'error' | 'info' | 'default' }> = {
    completed: { color: 'success' },
    running: { color: 'info' },
    queued: { color: 'warning' },
    pending: { color: 'default' },
    failed: { color: 'error' },
    cancelled: { color: 'default' },
  };

  const config = statusConfig[status] || statusConfig.pending;

  return (
    <Chip
      size="small"
      label={status.charAt(0).toUpperCase() + status.slice(1)}
      color={config.color}
    />
  );
};

const HistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  // State
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedScan, setSelectedScan] = useState<any>(null);

  // Fetch scans
  const { data: scans, isLoading, refetch } = useQuery({
    queryKey: ['scans', page, rowsPerPage, statusFilter],
    queryFn: () =>
      scansApi.list({
        page: page + 1,
        per_page: rowsPerPage,
        status: statusFilter === 'all' ? undefined : statusFilter,
      }),
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => scansApi.delete(scanId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] });
      handleMenuClose();
    },
  });

  // Export mutation
  const exportMutation = useMutation({
    mutationFn: (scanId: string) => reportsApi.generate(scanId, 'pdf'),
    onSuccess: (data) => {
      window.open(`/api/v1/reports/${data.report_id}/download`, '_blank');
      handleMenuClose();
    },
  });

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, scan: any) => {
    event.stopPropagation();
    setAnchorEl(event.currentTarget);
    setSelectedScan(scan);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
    setSelectedScan(null);
  };

  const handleRowClick = (scanId: string) => {
    navigate(`/scan/${scanId}`);
  };

  // Filter scans by search query
  const filteredScans = scans?.items?.filter((scan: any) =>
    scan.target_value.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Scan History
          </Typography>
          <Typography variant="body2" color="text.secondary">
            View and manage past vulnerability scans
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <IconButton onClick={() => refetch()}>
            <RefreshIcon />
          </IconButton>
          <Button variant="contained" onClick={() => navigate('/scan')}>
            New Scan
          </Button>
        </Stack>
      </Stack>

      {/* Filters */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField
              placeholder="Search by target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              size="small"
              sx={{ flex: 1 }}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
              }}
            />
            <FormControl size="small" sx={{ minWidth: 150 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={statusFilter}
                label="Status"
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <MenuItem value="all">All</MenuItem>
                <MenuItem value="completed">Completed</MenuItem>
                <MenuItem value="running">Running</MenuItem>
                <MenuItem value="queued">Queued</MenuItem>
                <MenuItem value="failed">Failed</MenuItem>
                <MenuItem value="cancelled">Cancelled</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </CardContent>
      </Card>

      {/* Table */}
      <Card>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Target</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="center">Critical</TableCell>
                <TableCell align="center">High</TableCell>
                <TableCell align="center">Total</TableCell>
                <TableCell>Date</TableCell>
                <TableCell width={50}></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredScans.map((scan: any) => (
                <TableRow
                  key={scan.scan_id}
                  hover
                  sx={{ cursor: 'pointer' }}
                  onClick={() => handleRowClick(scan.scan_id)}
                >
                  <TableCell>
                    <Typography variant="body2" fontWeight="medium">
                      {scan.target_value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {scan.scan_id.slice(0, 8)}...
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={scan.scan_type} variant="outlined" />
                  </TableCell>
                  <TableCell>
                    <StatusChip status={scan.status} />
                  </TableCell>
                  <TableCell align="center">
                    {scan.critical_count > 0 ? (
                      <Chip
                        size="small"
                        label={scan.critical_count}
                        sx={{ bgcolor: SEVERITY_COLORS.critical, color: 'white' }}
                      />
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell align="center">
                    {scan.high_count > 0 ? (
                      <Chip
                        size="small"
                        label={scan.high_count}
                        sx={{ bgcolor: SEVERITY_COLORS.high, color: 'white' }}
                      />
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell align="center">{scan.total_findings || 0}</TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {format(new Date(scan.created_at), 'MMM d, yyyy')}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {format(new Date(scan.created_at), 'HH:mm')}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <IconButton
                      size="small"
                      onClick={(e) => handleMenuOpen(e, scan)}
                    >
                      <MoreIcon />
                    </IconButton>
                  </TableCell>
                </TableRow>
              ))}
              {filteredScans.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} align="center" sx={{ py: 4 }}>
                    <Typography color="text.secondary">
                      {isLoading ? 'Loading...' : 'No scans found'}
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        <TablePagination
          component="div"
          count={scans?.total || 0}
          page={page}
          onPageChange={(_, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
          rowsPerPageOptions={[5, 10, 25, 50]}
        />
      </Card>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem
          onClick={() => {
            navigate(`/scan/${selectedScan?.scan_id}`);
            handleMenuClose();
          }}
        >
          <ListItemIcon>
            <ViewIcon fontSize="small" />
          </ListItemIcon>
          View Details
        </MenuItem>
        {selectedScan?.status === 'completed' && (
          <MenuItem
            onClick={() => exportMutation.mutate(selectedScan.scan_id)}
            disabled={exportMutation.isPending}
          >
            <ListItemIcon>
              <DownloadIcon fontSize="small" />
            </ListItemIcon>
            Export Report
          </MenuItem>
        )}
        <MenuItem
          onClick={() => deleteMutation.mutate(selectedScan?.scan_id)}
          disabled={deleteMutation.isPending}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          Delete
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default HistoryPage;
