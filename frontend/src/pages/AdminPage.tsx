import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  Button,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Grid,
  Alert,
  LinearProgress,
  Paper,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Person as PersonIcon,
  Settings as SettingsIcon,
  History as HistoryIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { format } from 'date-fns';
import { adminApi } from '../services/api';

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

const RoleChip: React.FC<{ role: string }> = ({ role }) => {
  const roleConfig: Record<string, { color: 'error' | 'warning' | 'info' | 'default' }> = {
    admin: { color: 'error' },
    manager: { color: 'warning' },
    analyst: { color: 'info' },
  };
  const config = roleConfig[role] || roleConfig.analyst;
  return <Chip size="small" label={role} color={config.color} />;
};

const AdminPage: React.FC = () => {
  const queryClient = useQueryClient();
  const [tabValue, setTabValue] = useState(0);
  
  // User management state
  const [userDialogOpen, setUserDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<any>(null);
  const [userForm, setUserForm] = useState({
    username: '',
    email: '',
    password: '',
    role: 'analyst',
    is_active: true,
  });

  // Fetch users
  const { data: users, isLoading: usersLoading } = useQuery({
    queryKey: ['admin-users'],
    queryFn: () => adminApi.getUsers(),
  });

  // Fetch settings
  const { data: settings, isLoading: settingsLoading } = useQuery({
    queryKey: ['admin-settings'],
    queryFn: () => adminApi.getSystemSettings(),
  });

  // Fetch audit logs
  const { data: auditLogs, isLoading: auditLoading } = useQuery({
    queryKey: ['admin-audit-logs'],
    queryFn: () => adminApi.getAuditLogs({ per_page: 50 }),
  });

  // Create user mutation
  const createUserMutation = useMutation({
    mutationFn: (data: any) => adminApi.createUser(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      handleCloseUserDialog();
    },
  });

  // Update user mutation
  const updateUserMutation = useMutation({
    mutationFn: ({ userId, data }: { userId: string; data: any }) =>
      adminApi.updateUser(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      handleCloseUserDialog();
    },
  });

  // Delete user mutation
  const deleteUserMutation = useMutation({
    mutationFn: (userId: string) => adminApi.deleteUser(userId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    },
  });

  // Update settings mutation
  const updateSettingsMutation = useMutation({
    mutationFn: (data: any) => adminApi.updateSystemSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin-settings'] });
    },
  });

  const handleOpenUserDialog = (user?: any) => {
    if (user) {
      setEditingUser(user);
      setUserForm({
        username: user.username,
        email: user.email,
        password: '',
        role: user.role,
        is_active: user.is_active,
      });
    } else {
      setEditingUser(null);
      setUserForm({
        username: '',
        email: '',
        password: '',
        role: 'analyst',
        is_active: true,
      });
    }
    setUserDialogOpen(true);
  };

  const handleCloseUserDialog = () => {
    setUserDialogOpen(false);
    setEditingUser(null);
  };

  const handleSaveUser = () => {
    if (editingUser) {
      updateUserMutation.mutate({
        userId: editingUser.id,
        data: {
          email: userForm.email,
          role: userForm.role,
          is_active: userForm.is_active,
        },
      });
    } else {
      createUserMutation.mutate(userForm);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Admin Panel
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Manage users, settings, and view audit logs
          </Typography>
        </Box>
      </Stack>

      {/* Tabs */}
      <Card>
        <Tabs
          value={tabValue}
          onChange={(_, newValue) => setTabValue(newValue)}
          sx={{ borderBottom: 1, borderColor: 'divider', px: 2 }}
        >
          <Tab icon={<PersonIcon />} label="Users" iconPosition="start" />
          <Tab icon={<SettingsIcon />} label="System Settings" iconPosition="start" />
          <Tab icon={<HistoryIcon />} label="Audit Logs" iconPosition="start" />
        </Tabs>

        {/* Users Tab */}
        <TabPanel value={tabValue} index={0}>
          <CardContent>
            <Stack direction="row" justifyContent="space-between" alignItems="center" mb={2}>
              <Typography variant="h6">User Management</Typography>
              <Button
                variant="contained"
                startIcon={<AddIcon />}
                onClick={() => handleOpenUserDialog()}
              >
                Add User
              </Button>
            </Stack>

            {usersLoading ? (
              <LinearProgress />
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Username</TableCell>
                      <TableCell>Email</TableCell>
                      <TableCell>Role</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Created</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {users?.items?.map((user: any) => (
                      <TableRow key={user.id}>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {user.username}
                          </Typography>
                        </TableCell>
                        <TableCell>{user.email}</TableCell>
                        <TableCell>
                          <RoleChip role={user.role} />
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={user.is_active ? 'Active' : 'Inactive'}
                            color={user.is_active ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          {format(new Date(user.created_at), 'MMM d, yyyy')}
                        </TableCell>
                        <TableCell align="right">
                          <IconButton
                            size="small"
                            onClick={() => handleOpenUserDialog(user)}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => deleteUserMutation.mutate(user.id)}
                            disabled={user.username === 'admin'}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </TabPanel>

        {/* Settings Tab */}
        <TabPanel value={tabValue} index={1}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              System Settings
            </Typography>

            {settingsLoading ? (
              <LinearProgress />
            ) : (
              <Grid container spacing={3}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                      Scan Configuration
                    </Typography>
                    <Stack spacing={2}>
                      <TextField
                        label="Max Concurrent Scans"
                        type="number"
                        defaultValue={settings?.max_concurrent_scans || 5}
                        size="small"
                        fullWidth
                      />
                      <TextField
                        label="Scan Timeout (minutes)"
                        type="number"
                        defaultValue={settings?.scan_timeout_minutes || 60}
                        size="small"
                        fullWidth
                      />
                      <FormControlLabel
                        control={
                          <Switch
                            defaultChecked={settings?.require_approval ?? true}
                          />
                        }
                        label="Require approval for external targets"
                      />
                    </Stack>
                  </Paper>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                      Resource Limits
                    </Typography>
                    <Stack spacing={2}>
                      <TextField
                        label="Max CPU Usage (%)"
                        type="number"
                        defaultValue={settings?.max_cpu_percent || 80}
                        size="small"
                        fullWidth
                      />
                      <TextField
                        label="Max Memory Usage (%)"
                        type="number"
                        defaultValue={settings?.max_memory_percent || 80}
                        size="small"
                        fullWidth
                      />
                      <TextField
                        label="Results Retention (days)"
                        type="number"
                        defaultValue={settings?.retention_days || 90}
                        size="small"
                        fullWidth
                      />
                    </Stack>
                  </Paper>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                      Scanner Status
                    </Typography>
                    <TableContainer>
                      <Table size="small">
                        <TableBody>
                          {['OpenVAS', 'Nuclei', 'OWASP ZAP', 'Nmap', 'Nikto', 'SQLmap'].map(
                            (scanner) => (
                              <TableRow key={scanner}>
                                <TableCell>{scanner}</TableCell>
                                <TableCell align="right">
                                  <Chip size="small" label="Online" color="success" />
                                </TableCell>
                              </TableRow>
                            )
                          )}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Paper>
                </Grid>

                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 3 }}>
                    <Typography variant="subtitle1" fontWeight="medium" gutterBottom>
                      Email Configuration
                    </Typography>
                    <Stack spacing={2}>
                      <TextField
                        label="SMTP Server"
                        defaultValue={settings?.smtp_server || ''}
                        size="small"
                        fullWidth
                      />
                      <TextField
                        label="SMTP Port"
                        type="number"
                        defaultValue={settings?.smtp_port || 587}
                        size="small"
                        fullWidth
                      />
                      <TextField
                        label="From Email"
                        defaultValue={settings?.from_email || ''}
                        size="small"
                        fullWidth
                      />
                    </Stack>
                  </Paper>
                </Grid>

                <Grid item xs={12}>
                  <Button variant="contained" startIcon={<RefreshIcon />}>
                    Save Settings
                  </Button>
                </Grid>
              </Grid>
            )}
          </CardContent>
        </TabPanel>

        {/* Audit Logs Tab */}
        <TabPanel value={tabValue} index={2}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Audit Logs
            </Typography>

            {auditLoading ? (
              <LinearProgress />
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>Timestamp</TableCell>
                      <TableCell>User</TableCell>
                      <TableCell>Action</TableCell>
                      <TableCell>Resource</TableCell>
                      <TableCell>Details</TableCell>
                      <TableCell>IP Address</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {auditLogs?.items?.map((log: any) => (
                      <TableRow key={log.id}>
                        <TableCell>
                          {format(new Date(log.created_at), 'MMM d, yyyy HH:mm:ss')}
                        </TableCell>
                        <TableCell>{log.username}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={log.action}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>{log.resource_type}</TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}
                          >
                            {log.details || '-'}
                          </Typography>
                        </TableCell>
                        <TableCell>{log.ip_address}</TableCell>
                      </TableRow>
                    )) || (
                      <TableRow>
                        <TableCell colSpan={6} align="center">
                          No audit logs available
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </TabPanel>
      </Card>

      {/* User Dialog */}
      <Dialog
        open={userDialogOpen}
        onClose={handleCloseUserDialog}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>{editingUser ? 'Edit User' : 'Add User'}</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 1 }}>
            <TextField
              label="Username"
              value={userForm.username}
              onChange={(e) => setUserForm({ ...userForm, username: e.target.value })}
              fullWidth
              disabled={!!editingUser}
            />
            <TextField
              label="Email"
              type="email"
              value={userForm.email}
              onChange={(e) => setUserForm({ ...userForm, email: e.target.value })}
              fullWidth
            />
            {!editingUser && (
              <TextField
                label="Password"
                type="password"
                value={userForm.password}
                onChange={(e) => setUserForm({ ...userForm, password: e.target.value })}
                fullWidth
              />
            )}
            <FormControl fullWidth>
              <InputLabel>Role</InputLabel>
              <Select
                value={userForm.role}
                label="Role"
                onChange={(e) => setUserForm({ ...userForm, role: e.target.value })}
              >
                <MenuItem value="admin">Admin</MenuItem>
                <MenuItem value="manager">Manager</MenuItem>
                <MenuItem value="analyst">Analyst</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              control={
                <Switch
                  checked={userForm.is_active}
                  onChange={(e) => setUserForm({ ...userForm, is_active: e.target.checked })}
                />
              }
              label="Active"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseUserDialog}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveUser}
            disabled={
              createUserMutation.isPending ||
              updateUserMutation.isPending ||
              !userForm.username ||
              !userForm.email ||
              (!editingUser && !userForm.password)
            }
          >
            {editingUser ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AdminPage;
