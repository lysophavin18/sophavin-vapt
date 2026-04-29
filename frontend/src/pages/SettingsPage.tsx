import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Stack,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Divider,
  Grid,
  Avatar,
  Alert,
  Snackbar,
  Tab,
  Tabs,
  InputAdornment,
  IconButton,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Save as SaveIcon,
  Person as PersonIcon,
  Notifications as NotificationsIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useMutation } from '@tanstack/react-query';
import { useAuthStore } from '../stores/authStore';
import { api } from '../services/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <Box hidden={value !== index} sx={{ pt: 3 }}>
    {value === index && children}
  </Box>
);

const SettingsPage: React.FC = () => {
  const { user, updateUser } = useAuthStore();
  const [tabValue, setTabValue] = useState(0);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' });

  // Profile state
  const [profile, setProfile] = useState({
    username: user?.username || '',
    email: user?.email || '',
  });

  // Password state
  const [passwords, setPasswords] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  });
  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  });

  // Notification settings
  const [notifications, setNotifications] = useState({
    emailOnScanComplete: true,
    emailOnCriticalFinding: true,
    browserNotifications: true,
    weeklyDigest: false,
  });

  // Update profile mutation
  const updateProfileMutation = useMutation({
    mutationFn: (data: { email: string }) =>
      api.patch('/api/v1/users/me', data),
    onSuccess: (response: { data: any }) => {
      updateUser(response.data);
      setSnackbar({ open: true, message: 'Profile updated successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to update profile', severity: 'error' });
    },
  });

  // Change password mutation
  const changePasswordMutation = useMutation({
    mutationFn: (data: { current_password: string; new_password: string }) =>
      api.post('/api/v1/users/me/change-password', data),
    onSuccess: () => {
      setPasswords({ currentPassword: '', newPassword: '', confirmPassword: '' });
      setSnackbar({ open: true, message: 'Password changed successfully', severity: 'success' });
    },
    onError: () => {
      setSnackbar({ open: true, message: 'Failed to change password', severity: 'error' });
    },
  });

  const handleSaveProfile = () => {
    updateProfileMutation.mutate({ email: profile.email });
  };

  const handleChangePassword = () => {
    if (passwords.newPassword !== passwords.confirmPassword) {
      setSnackbar({ open: true, message: 'Passwords do not match', severity: 'error' });
      return;
    }
    if (passwords.newPassword.length < 8) {
      setSnackbar({ open: true, message: 'Password must be at least 8 characters', severity: 'error' });
      return;
    }
    changePasswordMutation.mutate({
      current_password: passwords.currentPassword,
      new_password: passwords.newPassword,
    });
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Stack direction="row" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" fontWeight="bold">
            Settings
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Manage your account and preferences
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
          <Tab icon={<PersonIcon />} label="Profile" iconPosition="start" />
          <Tab icon={<SecurityIcon />} label="Security" iconPosition="start" />
          <Tab icon={<NotificationsIcon />} label="Notifications" iconPosition="start" />
        </Tabs>

        {/* Profile Tab */}
        <TabPanel value={tabValue} index={0}>
          <CardContent>
            <Grid container spacing={4}>
              <Grid item xs={12} md={4}>
                <Stack alignItems="center" spacing={2}>
                  <Avatar
                    sx={{ width: 120, height: 120, fontSize: 48, bgcolor: 'primary.main' }}
                  >
                    {user?.username?.charAt(0).toUpperCase() || 'U'}
                  </Avatar>
                  <Typography variant="h6">{user?.username}</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Role: {user?.role || 'analyst'}
                  </Typography>
                </Stack>
              </Grid>
              <Grid item xs={12} md={8}>
                <Stack spacing={3}>
                  <TextField
                    label="Username"
                    value={profile.username}
                    disabled
                    fullWidth
                    helperText="Username cannot be changed"
                  />
                  <TextField
                    label="Email"
                    type="email"
                    value={profile.email}
                    onChange={(e) => setProfile({ ...profile, email: e.target.value })}
                    fullWidth
                  />
                  <Box>
                    <Button
                      variant="contained"
                      startIcon={<SaveIcon />}
                      onClick={handleSaveProfile}
                      disabled={updateProfileMutation.isPending}
                    >
                      Save Changes
                    </Button>
                  </Box>
                </Stack>
              </Grid>
            </Grid>
          </CardContent>
        </TabPanel>

        {/* Security Tab */}
        <TabPanel value={tabValue} index={1}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Change Password
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={3}>
              Update your password to keep your account secure
            </Typography>
            <Stack spacing={3} maxWidth={400}>
              <TextField
                label="Current Password"
                type={showPasswords.current ? 'text' : 'password'}
                value={passwords.currentPassword}
                onChange={(e) => setPasswords({ ...passwords, currentPassword: e.target.value })}
                fullWidth
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPasswords({ ...showPasswords, current: !showPasswords.current })}
                        edge="end"
                      >
                        {showPasswords.current ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
              <TextField
                label="New Password"
                type={showPasswords.new ? 'text' : 'password'}
                value={passwords.newPassword}
                onChange={(e) => setPasswords({ ...passwords, newPassword: e.target.value })}
                fullWidth
                helperText="Minimum 8 characters"
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPasswords({ ...showPasswords, new: !showPasswords.new })}
                        edge="end"
                      >
                        {showPasswords.new ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
              <TextField
                label="Confirm New Password"
                type={showPasswords.confirm ? 'text' : 'password'}
                value={passwords.confirmPassword}
                onChange={(e) => setPasswords({ ...passwords, confirmPassword: e.target.value })}
                fullWidth
                error={passwords.confirmPassword !== '' && passwords.newPassword !== passwords.confirmPassword}
                helperText={
                  passwords.confirmPassword !== '' && passwords.newPassword !== passwords.confirmPassword
                    ? 'Passwords do not match'
                    : ''
                }
                InputProps={{
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPasswords({ ...showPasswords, confirm: !showPasswords.confirm })}
                        edge="end"
                      >
                        {showPasswords.confirm ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
              />
              <Box>
                <Button
                  variant="contained"
                  onClick={handleChangePassword}
                  disabled={
                    changePasswordMutation.isPending ||
                    !passwords.currentPassword ||
                    !passwords.newPassword ||
                    passwords.newPassword !== passwords.confirmPassword
                  }
                >
                  Change Password
                </Button>
              </Box>
            </Stack>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h6" gutterBottom>
              Two-Factor Authentication
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={2}>
              Add an extra layer of security to your account
            </Typography>
            <Button variant="outlined">Enable 2FA</Button>
          </CardContent>
        </TabPanel>

        {/* Notifications Tab */}
        <TabPanel value={tabValue} index={2}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Email Notifications
            </Typography>
            <Stack spacing={2} mb={4}>
              <FormControlLabel
                control={
                  <Switch
                    checked={notifications.emailOnScanComplete}
                    onChange={(e) =>
                      setNotifications({ ...notifications, emailOnScanComplete: e.target.checked })
                    }
                  />
                }
                label="Email when scan completes"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={notifications.emailOnCriticalFinding}
                    onChange={(e) =>
                      setNotifications({ ...notifications, emailOnCriticalFinding: e.target.checked })
                    }
                  />
                }
                label="Email for critical findings"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={notifications.weeklyDigest}
                    onChange={(e) =>
                      setNotifications({ ...notifications, weeklyDigest: e.target.checked })
                    }
                  />
                }
                label="Weekly security digest"
              />
            </Stack>

            <Typography variant="h6" gutterBottom>
              Browser Notifications
            </Typography>
            <FormControlLabel
              control={
                <Switch
                  checked={notifications.browserNotifications}
                  onChange={(e) =>
                    setNotifications({ ...notifications, browserNotifications: e.target.checked })
                  }
                />
              }
              label="Enable browser notifications"
            />

            <Box mt={4}>
              <Button variant="contained" startIcon={<SaveIcon />}>
                Save Preferences
              </Button>
            </Box>
          </CardContent>
        </TabPanel>
      </Card>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default SettingsPage;
