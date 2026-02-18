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
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  Stepper,
  Step,
  StepLabel,
  Grid,
  Divider,
  Paper,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  ArrowBack as BackIcon,
  ArrowForward as ForwardIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Tune as TuneIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { scansApi } from '../services/api';

const SCAN_TYPES = [
  {
    value: 'quick',
    label: 'Quick Scan',
    description: 'Fast port scan and basic vulnerability check',
    icon: <SpeedIcon />,
    duration: '5-15 minutes',
    tools: ['nmap', 'nuclei'],
  },
  {
    value: 'full',
    label: 'Full Scan',
    description: 'Comprehensive vulnerability assessment with all tools',
    icon: <SecurityIcon />,
    duration: '30-60 minutes',
    tools: ['nmap', 'openvas', 'nuclei', 'zap', 'nikto', 'sqlmap'],
  },
  {
    value: 'web',
    label: 'Web Application Scan',
    description: 'Deep web application security testing',
    icon: <TuneIcon />,
    duration: '20-45 minutes',
    tools: ['nuclei', 'zap', 'nikto', 'sqlmap'],
  },
  {
    value: 'container_only',
    label: 'Container Security Scan',
    description: 'Docker/container image vulnerability scanning',
    icon: <SecurityIcon />,
    duration: '15-30 minutes',
    tools: ['trivy', 'docker_bench', 'clair', 'falco'],
  },
  {
    value: 'cloud_only',
    label: 'Cloud Security Scan',
    description: 'Multi-cloud security posture assessment (AWS/Azure/GCP)',
    icon: <SecurityIcon />,
    duration: '30-60 minutes',
    tools: ['scoutsuite', 'prowler'],
  },
  {
    value: 'iac_only',
    label: 'Infrastructure as Code Scan',
    description: 'Terraform/CloudFormation/Kubernetes YAML scanning',
    icon: <TuneIcon />,
    duration: '10-20 minutes',
    tools: ['checkov', 'terrascan'],
  },
  {
    value: 'kubernetes_only',
    label: 'Kubernetes Security Scan',
    description: 'Kubernetes cluster security assessment',
    icon: <SecurityIcon />,
    duration: '15-30 minutes',
    tools: ['kube_hunter', 'kube_bench'],
  },
  {
    value: 'api_only',
    label: 'API Security Scan',
    description: 'REST/GraphQL API vulnerability testing and fuzzing',
    icon: <TuneIcon />,
    duration: '15-30 minutes',
    tools: ['arjun', 'graphqlmap', 'jwt_tool', 'wfuzz', 'newman'],
  },
  {
    value: 'custom',
    label: 'Custom Scan',
    description: 'Select specific tools and options',
    icon: <TuneIcon />,
    duration: 'Varies',
    tools: [],
  },
];

const AVAILABLE_TOOLS = [
  // Network & Vulnerability Tools
  { id: 'nmap', label: 'Nmap', description: 'Network discovery and port scanning', category: 'network' },
  { id: 'openvas', label: 'OpenVAS', description: 'Comprehensive vulnerability scanner', category: 'network' },
  { id: 'nuclei', label: 'Nuclei', description: 'Template-based vulnerability detection', category: 'network' },
  // Web Application Tools
  { id: 'zap', label: 'OWASP ZAP', description: 'Web application security scanner', category: 'web' },
  { id: 'nikto', label: 'Nikto', description: 'Web server scanner', category: 'web' },
  { id: 'sqlmap', label: 'SQLmap', description: 'SQL injection detection', category: 'web' },
  // Container Security Tools
  { id: 'trivy', label: 'Trivy', description: 'Container image vulnerability scanner', category: 'container' },
  { id: 'docker_bench', label: 'Docker Bench', description: 'Docker CIS benchmark security audit', category: 'container' },
  { id: 'clair', label: 'Clair', description: 'Container vulnerability analysis', category: 'container' },
  { id: 'falco', label: 'Falco', description: 'Runtime security monitoring', category: 'container' },
  // Cloud Security Tools
  { id: 'scoutsuite', label: 'ScoutSuite', description: 'Multi-cloud security auditing (AWS/Azure/GCP)', category: 'cloud' },
  { id: 'prowler', label: 'Prowler', description: 'AWS security assessment tool', category: 'cloud' },
  // IaC Security Tools
  { id: 'checkov', label: 'Checkov', description: 'Infrastructure as Code scanning', category: 'iac' },
  { id: 'terrascan', label: 'Terrascan', description: 'IaC policy enforcement', category: 'iac' },
  // Kubernetes Security Tools
  { id: 'kube_hunter', label: 'Kube-hunter', description: 'Kubernetes penetration testing', category: 'kubernetes' },
  { id: 'kube_bench', label: 'Kube-bench', description: 'CIS Kubernetes benchmark', category: 'kubernetes' },
  // API Security Tools
  { id: 'arjun', label: 'Arjun', description: 'HTTP parameter discovery', category: 'api' },
  { id: 'graphqlmap', label: 'GraphQLmap', description: 'GraphQL security testing', category: 'api' },
  { id: 'jwt_tool', label: 'JWT_Tool', description: 'JWT token analysis and attacks', category: 'api' },
  { id: 'wfuzz', label: 'wfuzz', description: 'Web/API fuzzing', category: 'api' },
  { id: 'newman', label: 'Newman', description: 'Postman API collection testing', category: 'api' },
];

const steps = ['Target', 'Scan Type', 'Configuration', 'Review'];

const ScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [activeStep, setActiveStep] = useState(0);
  const [error, setError] = useState('');
  
  // Form state
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [selectedTools, setSelectedTools] = useState<string[]>(['nmap', 'openvas', 'nuclei', 'zap', 'nikto', 'sqlmap']);
  const [options, setOptions] = useState({
    aggressive: false,
    followRedirects: true,
    includeSqlInjection: true,
    includeXss: true,
    maxDepth: 3,
    threads: 10,
  });

  // Create scan mutation
  const createScanMutation = useMutation({
    mutationFn: () =>
      scansApi.create({
        target,
        scan_type: scanType,
        tools: selectedTools,
        options,
      }),
    onSuccess: (data) => {
      navigate(`/scan/${data.scan_id}`);
    },
    onError: (err: any) => {
      setError(err.response?.data?.detail || 'Failed to create scan');
    },
  });

  const handleNext = () => {
    if (activeStep === 0 && !target.trim()) {
      setError('Please enter a target');
      return;
    }
    setError('');
    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setActiveStep((prev) => prev - 1);
  };

  const handleToolToggle = (toolId: string) => {
    setSelectedTools((prev) =>
      prev.includes(toolId)
        ? prev.filter((t) => t !== toolId)
        : [...prev, toolId]
    );
  };

  const handleScanTypeChange = (value: string) => {
    setScanType(value);
    const scanTypeConfig = SCAN_TYPES.find((t) => t.value === value);
    if (scanTypeConfig && scanTypeConfig.tools.length > 0) {
      setSelectedTools(scanTypeConfig.tools);
    }
  };

  const handleSubmit = () => {
    createScanMutation.mutate();
  };

  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Enter Target
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={3}>
              Enter an IP address, hostname, or URL to scan
            </Typography>
            <TextField
              fullWidth
              label="Target"
              placeholder="e.g., 192.168.1.1, example.com, https://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              helperText="Supports IP addresses, CIDR ranges, hostnames, and URLs"
            />
          </Box>
        );

      case 1:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Select Scan Type
            </Typography>
            <Grid container spacing={2}>
              {SCAN_TYPES.map((type) => (
                <Grid item xs={12} sm={6} key={type.value}>
                  <Paper
                    sx={{
                      p: 2,
                      cursor: 'pointer',
                      border: 2,
                      borderColor:
                        scanType === type.value ? 'primary.main' : 'transparent',
                      '&:hover': {
                        bgcolor: 'action.hover',
                      },
                    }}
                    onClick={() => handleScanTypeChange(type.value)}
                  >
                    <Stack direction="row" spacing={2} alignItems="flex-start">
                      <Box sx={{ color: 'primary.main' }}>{type.icon}</Box>
                      <Box>
                        <Typography fontWeight="medium">{type.label}</Typography>
                        <Typography variant="body2" color="text.secondary">
                          {type.description}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Duration: {type.duration}
                        </Typography>
                        {type.tools.length > 0 && (
                          <Stack direction="row" spacing={0.5} mt={1} flexWrap="wrap">
                            {type.tools.map((tool) => (
                              <Chip
                                key={tool}
                                label={tool}
                                size="small"
                                sx={{ mb: 0.5 }}
                              />
                            ))}
                          </Stack>
                        )}
                      </Box>
                    </Stack>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        );

      case 2:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Configure Scan
            </Typography>
            
            {/* Tool Selection */}
            <Typography variant="subtitle2" gutterBottom>
              Select Tools
            </Typography>
            <FormGroup row sx={{ mb: 3 }}>
              {AVAILABLE_TOOLS.map((tool) => (
                <FormControlLabel
                  key={tool.id}
                  control={
                    <Checkbox
                      checked={selectedTools.includes(tool.id)}
                      onChange={() => handleToolToggle(tool.id)}
                      disabled={scanType !== 'custom'}
                    />
                  }
                  label={
                    <Stack>
                      <Typography variant="body2">{tool.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {tool.description}
                      </Typography>
                    </Stack>
                  }
                  sx={{ width: '50%', mb: 1 }}
                />
              ))}
            </FormGroup>

            <Divider sx={{ my: 2 }} />

            {/* Options */}
            <Typography variant="subtitle2" gutterBottom>
              Scan Options
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={options.aggressive}
                      onChange={(e) =>
                        setOptions({ ...options, aggressive: e.target.checked })
                      }
                    />
                  }
                  label="Aggressive scan (faster, more detectable)"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={options.followRedirects}
                      onChange={(e) =>
                        setOptions({ ...options, followRedirects: e.target.checked })
                      }
                    />
                  }
                  label="Follow redirects"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  type="number"
                  label="Max depth"
                  value={options.maxDepth}
                  onChange={(e) =>
                    setOptions({ ...options, maxDepth: parseInt(e.target.value) || 3 })
                  }
                  inputProps={{ min: 1, max: 10 }}
                  size="small"
                  fullWidth
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  type="number"
                  label="Threads"
                  value={options.threads}
                  onChange={(e) =>
                    setOptions({ ...options, threads: parseInt(e.target.value) || 10 })
                  }
                  inputProps={{ min: 1, max: 50 }}
                  size="small"
                  fullWidth
                />
              </Grid>
            </Grid>
          </Box>
        );

      case 3:
        return (
          <Box>
            <Typography variant="h6" gutterBottom>
              Review Scan Configuration
            </Typography>
            <Card sx={{ bgcolor: 'background.default' }}>
              <CardContent>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">
                      Target
                    </Typography>
                    <Typography variant="body1" fontWeight="medium">
                      {target}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">
                      Scan Type
                    </Typography>
                    <Typography variant="body1" fontWeight="medium">
                      {SCAN_TYPES.find((t) => t.value === scanType)?.label}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Tools
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      {selectedTools.map((tool) => (
                        <Chip key={tool} label={tool} size="small" sx={{ mb: 0.5 }} />
                      ))}
                    </Stack>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      Options
                    </Typography>
                    <Typography variant="body2">
                      Aggressive: {options.aggressive ? 'Yes' : 'No'} | 
                      Max Depth: {options.maxDepth} | 
                      Threads: {options.threads}
                    </Typography>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>

            <Alert severity="info" sx={{ mt: 2 }}>
              The scan will be queued and executed based on system resources. 
              You will be redirected to monitor progress.
            </Alert>
          </Box>
        );

      default:
        return null;
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            New Scan
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Configure and start a new vulnerability scan
          </Typography>
        </Box>
      </Stack>

      {/* Stepper */}
      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {steps.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {/* Content */}
      <Card>
        <CardContent sx={{ p: 3 }}>
          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          {renderStepContent()}

          {/* Navigation */}
          <Stack direction="row" justifyContent="space-between" mt={4}>
            <Button
              startIcon={<BackIcon />}
              onClick={activeStep === 0 ? () => navigate('/dashboard') : handleBack}
            >
              {activeStep === 0 ? 'Cancel' : 'Back'}
            </Button>
            
            {activeStep < steps.length - 1 ? (
              <Button
                variant="contained"
                endIcon={<ForwardIcon />}
                onClick={handleNext}
              >
                Next
              </Button>
            ) : (
              <Button
                variant="contained"
                color="primary"
                startIcon={<PlayIcon />}
                onClick={handleSubmit}
                disabled={createScanMutation.isPending}
              >
                {createScanMutation.isPending ? 'Starting...' : 'Start Scan'}
              </Button>
            )}
          </Stack>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ScanPage;
