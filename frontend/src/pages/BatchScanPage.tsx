import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Stack,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  Paper,
  Grid,
  IconButton,
  Tooltip,
  Slider,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  LinearProgress,
  RadioGroup,
  Radio,
  FormControlLabel,
} from '@mui/material';
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  PlayArrow as PlayIcon,
  Speed as SpeedIcon,
  Schedule as ScheduleIcon,
  Memory as MemoryIcon,
  Build as BuildIcon,
  List as ListIcon,
  ArrowBack as BackIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';

// Schedule strategies with descriptions
const SCHEDULE_STRATEGIES = [
  {
    value: 'resource_aware',
    label: 'Resource-Aware (Recommended)',
    description: 'Dynamically adjusts concurrency based on system load for optimal performance',
    icon: <MemoryIcon />,
  },
  {
    value: 'parallel',
    label: 'Parallel',
    description: 'Scan all targets simultaneously up to max concurrent limit',
    icon: <SpeedIcon />,
  },
  {
    value: 'staggered',
    label: 'Staggered',
    description: 'Start new scans at regular intervals to spread the load',
    icon: <ScheduleIcon />,
  },
  {
    value: 'sequential',
    label: 'Sequential',
    description: 'Scan one target at a time in order',
    icon: <ListIcon />,
  },
  {
    value: 'tool_optimized',
    label: 'Tool-Optimized',
    description: 'Run the same tool across all targets before moving to the next tool',
    icon: <BuildIcon />,
  },
];

const SCAN_TYPES = [
  { value: 'quick', label: 'Quick Scan' },
  { value: 'full', label: 'Full Scan' },
  { value: 'web_only', label: 'Web Application Scan' },
  { value: 'network_only', label: 'Network Scan' },
  { value: 'container_only', label: 'Container Security' },
  { value: 'cloud_only', label: 'Cloud Security' },
  { value: 'api_only', label: 'API Security' },
  { value: 'iac_only', label: 'IaC Security' },
  { value: 'kubernetes_only', label: 'Kubernetes Security' },
];

interface Target {
  id: string;
  value: string;
  isValid: boolean;
  error?: string;
}

const BatchScanPage: React.FC = () => {
  const navigate = useNavigate();
  
  // Form state
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targets, setTargets] = useState<Target[]>([{ id: '1', value: '', isValid: true }]);
  const [scanType, setScanType] = useState('full');
  const [strategy, setStrategy] = useState('resource_aware');
  const [maxConcurrent, setMaxConcurrent] = useState(3);
  const [staggerMinutes, setStaggerMinutes] = useState(5);
  const [priority, setPriority] = useState(5);
  const [scheduleType, setScheduleType] = useState<'immediate' | 'scheduled'>('immediate');
  const [scheduledAt, setScheduledAt] = useState<Date | null>(null);
  const [bulkInput, setBulkInput] = useState('');
  const [showBulkInput, setShowBulkInput] = useState(false);
  
  // Error state
  const [error, setError] = useState<string | null>(null);

  // API mutation
  const createBatchMutation = useMutation({
    mutationFn: async (data: any) => {
      const response = await fetch('/api/v1/batch-scans/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!response.ok) {
        const err = await response.json();
        throw new Error(err.detail || 'Failed to create batch scan');
      }
      return response.json();
    },
    onSuccess: (data) => {
      navigate(`/batch-scans/${data.batch_id}`);
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  // Validate target format
  const validateTarget = (value: string): { isValid: boolean; error?: string } => {
    if (!value.trim()) return { isValid: true };
    
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const urlPattern = /^https?:\/\/[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(\/.*)?$/;
    
    if (ipPattern.test(value) || domainPattern.test(value) || urlPattern.test(value)) {
      return { isValid: true };
    }
    return { isValid: false, error: 'Invalid IP, domain, or URL format' };
  };

  // Add new target
  const addTarget = () => {
    const newTarget: Target = {
      id: Date.now().toString(),
      value: '',
      isValid: true,
    };
    setTargets([...targets, newTarget]);
  };

  // Remove target
  const removeTarget = (id: string) => {
    if (targets.length > 1) {
      setTargets(targets.filter((t) => t.id !== id));
    }
  };

  // Update target
  const updateTarget = (id: string, value: string) => {
    const validation = validateTarget(value);
    setTargets(
      targets.map((t) =>
        t.id === id ? { ...t, value, isValid: validation.isValid, error: validation.error } : t
      )
    );
  };

  // Process bulk input
  const processBulkInput = () => {
    const lines = bulkInput.split('\n').filter((l) => l.trim());
    const newTargets: Target[] = lines.map((line, idx) => {
      const value = line.trim();
      const validation = validateTarget(value);
      return {
        id: `bulk-${Date.now()}-${idx}`,
        value,
        isValid: validation.isValid,
        error: validation.error,
      };
    });
    setTargets(newTargets);
    setShowBulkInput(false);
    setBulkInput('');
  };

  // Submit batch scan
  const handleSubmit = () => {
    setError(null);
    
    if (!name.trim()) {
      setError('Batch scan name is required');
      return;
    }
    
    const validTargets = targets.filter((t) => t.value.trim() && t.isValid);
    if (validTargets.length === 0) {
      setError('At least one valid target is required');
      return;
    }
    
    const data = {
      name: name.trim(),
      description: description.trim() || undefined,
      targets: validTargets.map((t) => ({ target: t.value, priority })),
      scan_type: scanType,
      schedule_strategy: strategy,
      max_concurrent: maxConcurrent,
      stagger_minutes: staggerMinutes,
      priority,
      scheduled_at: scheduleType === 'scheduled' && scheduledAt ? scheduledAt.toISOString() : undefined,
    };
    
    createBatchMutation.mutate(data);
  };

  const validTargetCount = targets.filter((t) => t.value.trim() && t.isValid).length;
  const estimatedDuration = Math.ceil(validTargetCount * 30 / maxConcurrent); // Rough estimate

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 3 }}>
          <IconButton onClick={() => navigate(-1)}>
            <BackIcon />
          </IconButton>
          <Typography variant="h4" fontWeight="bold">
            Create Batch Scan
          </Typography>
          <Chip label={`${validTargetCount} targets`} color="primary" />
        </Stack>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        <Grid container spacing={3}>
          {/* Left Column - Targets */}
          <Grid item xs={12} md={7}>
            <Card>
              <CardContent>
                <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                  <Typography variant="h6">Targets</Typography>
                  <Stack direction="row" spacing={1}>
                    <Button
                      size="small"
                      onClick={() => setShowBulkInput(!showBulkInput)}
                    >
                      {showBulkInput ? 'Single Input' : 'Bulk Input'}
                    </Button>
                    {!showBulkInput && (
                      <Button
                        size="small"
                        startIcon={<AddIcon />}
                        onClick={addTarget}
                      >
                        Add Target
                      </Button>
                    )}
                  </Stack>
                </Stack>

                {showBulkInput ? (
                  <Stack spacing={2}>
                    <TextField
                      multiline
                      rows={8}
                      fullWidth
                      label="Paste targets (one per line)"
                      placeholder="192.168.1.1&#10;example.com&#10;https://api.example.com/v1"
                      value={bulkInput}
                      onChange={(e) => setBulkInput(e.target.value)}
                    />
                    <Button onClick={processBulkInput} variant="contained">
                      Process {bulkInput.split('\n').filter((l) => l.trim()).length} Targets
                    </Button>
                  </Stack>
                ) : (
                  <Stack spacing={1}>
                    {targets.map((target) => (
                      <Stack key={target.id} direction="row" spacing={1} alignItems="flex-start">
                        <TextField
                          fullWidth
                          size="small"
                          placeholder="IP, domain, or URL"
                          value={target.value}
                          onChange={(e) => updateTarget(target.id, e.target.value)}
                          error={!target.isValid}
                          helperText={target.error}
                        />
                        <IconButton
                          onClick={() => removeTarget(target.id)}
                          disabled={targets.length === 1}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Stack>
                    ))}
                  </Stack>
                )}

                <Divider sx={{ my: 3 }} />

                {/* Scan Configuration */}
                <Typography variant="h6" sx={{ mb: 2 }}>
                  Scan Configuration
                </Typography>

                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      label="Batch Name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g., Weekly Infrastructure Scan"
                      required
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      multiline
                      rows={2}
                      label="Description (optional)"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <FormControl fullWidth>
                      <InputLabel>Scan Type</InputLabel>
                      <Select
                        value={scanType}
                        label="Scan Type"
                        onChange={(e) => setScanType(e.target.value)}
                      >
                        {SCAN_TYPES.map((type) => (
                          <MenuItem key={type.value} value={type.value}>
                            {type.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <FormControl fullWidth>
                      <InputLabel>Priority</InputLabel>
                      <Select
                        value={priority}
                        label="Priority"
                        onChange={(e) => setPriority(Number(e.target.value))}
                      >
                        {[...Array(10)].map((_, i) => (
                          <MenuItem key={i + 1} value={i + 1}>
                            {i + 1} {i === 0 && '(Highest)'} {i === 9 && '(Lowest)'}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Right Column - Strategy & Schedule */}
          <Grid item xs={12} md={5}>
            <Stack spacing={3}>
              {/* Strategy Selection */}
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ mb: 2 }}>
                    Scheduling Strategy
                  </Typography>

                  <RadioGroup
                    value={strategy}
                    onChange={(e) => setStrategy(e.target.value)}
                  >
                    {SCHEDULE_STRATEGIES.map((s) => (
                      <Paper
                        key={s.value}
                        sx={{
                          p: 2,
                          mb: 1,
                          cursor: 'pointer',
                          border: strategy === s.value ? '2px solid' : '1px solid',
                          borderColor: strategy === s.value ? 'primary.main' : 'divider',
                        }}
                        onClick={() => setStrategy(s.value)}
                      >
                        <FormControlLabel
                          value={s.value}
                          control={<Radio />}
                          label={
                            <Box>
                              <Stack direction="row" spacing={1} alignItems="center">
                                {s.icon}
                                <Typography fontWeight="medium">{s.label}</Typography>
                              </Stack>
                              <Typography variant="body2" color="text.secondary">
                                {s.description}
                              </Typography>
                            </Box>
                          }
                        />
                      </Paper>
                    ))}
                  </RadioGroup>

                  {/* Strategy-specific options */}
                  {(strategy === 'parallel' || strategy === 'resource_aware') && (
                    <Box sx={{ mt: 2 }}>
                      <Typography gutterBottom>
                        Max Concurrent Scans: {maxConcurrent}
                      </Typography>
                      <Slider
                        value={maxConcurrent}
                        onChange={(_, value) => setMaxConcurrent(value as number)}
                        min={1}
                        max={10}
                        marks
                        valueLabelDisplay="auto"
                      />
                    </Box>
                  )}

                  {strategy === 'staggered' && (
                    <Box sx={{ mt: 2 }}>
                      <Typography gutterBottom>
                        Stagger Interval: {staggerMinutes} minutes
                      </Typography>
                      <Slider
                        value={staggerMinutes}
                        onChange={(_, value) => setStaggerMinutes(value as number)}
                        min={1}
                        max={60}
                        valueLabelDisplay="auto"
                      />
                    </Box>
                  )}
                </CardContent>
              </Card>

              {/* Schedule */}
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ mb: 2 }}>
                    When to Run
                  </Typography>

                  <RadioGroup
                    value={scheduleType}
                    onChange={(e) => setScheduleType(e.target.value as 'immediate' | 'scheduled')}
                  >
                    <FormControlLabel
                      value="immediate"
                      control={<Radio />}
                      label="Run Immediately"
                    />
                    <FormControlLabel
                      value="scheduled"
                      control={<Radio />}
                      label="Schedule for Later"
                    />
                  </RadioGroup>

                  {scheduleType === 'scheduled' && (
                    <Box sx={{ mt: 2 }}>
                      <DateTimePicker
                        label="Scheduled Time"
                        value={scheduledAt}
                        onChange={(newValue) => setScheduledAt(newValue)}
                        slotProps={{ textField: { fullWidth: true } }}
                        minDateTime={new Date()}
                      />
                    </Box>
                  )}
                </CardContent>
              </Card>

              {/* Summary */}
              <Card>
                <CardContent>
                  <Typography variant="h6" sx={{ mb: 2 }}>
                    Summary
                  </Typography>

                  <TableContainer>
                    <Table size="small">
                      <TableBody>
                        <TableRow>
                          <TableCell>Targets</TableCell>
                          <TableCell align="right">{validTargetCount}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell>Scan Type</TableCell>
                          <TableCell align="right">
                            {SCAN_TYPES.find((t) => t.value === scanType)?.label}
                          </TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell>Strategy</TableCell>
                          <TableCell align="right">
                            {SCHEDULE_STRATEGIES.find((s) => s.value === strategy)?.label.replace(' (Recommended)', '')}
                          </TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell>Est. Duration</TableCell>
                          <TableCell align="right">~{estimatedDuration} min</TableCell>
                        </TableRow>
                      </TableBody>
                    </Table>
                  </TableContainer>

                  <Button
                    fullWidth
                    variant="contained"
                    size="large"
                    startIcon={<PlayIcon />}
                    onClick={handleSubmit}
                    disabled={createBatchMutation.isPending || validTargetCount === 0}
                    sx={{ mt: 2 }}
                  >
                    {createBatchMutation.isPending ? 'Creating...' : 'Start Batch Scan'}
                  </Button>
                </CardContent>
              </Card>
            </Stack>
          </Grid>
        </Grid>
      </Box>
    </LocalizationProvider>
  );
};

export default BatchScanPage;
