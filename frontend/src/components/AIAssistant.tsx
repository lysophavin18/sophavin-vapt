import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  Fab,
  Drawer,
  Paper,
  Typography,
  TextField,
  IconButton,
  Stack,
  Avatar,
  Chip,
  CircularProgress,
  Divider,
  Menu,
  MenuItem,
  Tooltip,
  Button,
  Collapse,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import {
  SmartToy as AIIcon,
  Send as SendIcon,
  Close as CloseIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  Assessment as AssessmentIcon,
  Psychology as PsychologyIcon,
  ContentCopy as CopyIcon,
  Refresh as RefreshIcon,
  Settings as SettingsIcon,
  Check as CheckIcon,
} from '@mui/icons-material';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  isStreaming?: boolean;
}

interface AIProvider {
  id: string;
  name: string;
  configured: boolean;
  default: boolean;
}

interface AIAssistantProps {
  scanId?: string;
  scanContext?: {
    target?: string;
    total_findings?: number;
    critical_count?: number;
    high_count?: number;
  };
}

const QUICK_ACTIONS = [
  { id: 'analyze', label: 'Analyze Scan', icon: <AssessmentIcon />, prompt: 'Analyze this scan and summarize the key findings.' },
  { id: 'remediation', label: 'Remediation Plan', icon: <BugIcon />, prompt: 'Create a prioritized remediation plan for the critical and high severity issues.' },
  { id: 'threat', label: 'Threat Intel', icon: <SecurityIcon />, prompt: 'What threat actors might exploit these vulnerabilities? Map to MITRE ATT&CK.' },
  { id: 'executive', label: 'Executive Summary', icon: <PsychologyIcon />, prompt: 'Write an executive summary suitable for non-technical leadership.' },
];

const AIAssistant: React.FC<AIAssistantProps> = ({ scanId, scanContext }) => {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [providers, setProviders] = useState<AIProvider[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string | null>(null);
  const [providerMenuAnchor, setProviderMenuAnchor] = useState<null | HTMLElement>(null);
  const [showQuickActions, setShowQuickActions] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch providers on mount
  useEffect(() => {
    const fetchProviders = async () => {
      try {
        const response = await fetch('/api/v1/ai/providers');
        if (response.ok) {
          const data = await response.json();
          setProviders(data);
          const defaultProvider = data.find((p: AIProvider) => p.default && p.configured);
          if (defaultProvider) {
            setSelectedProvider(defaultProvider.id);
          }
        }
      } catch (error) {
        console.error('Failed to fetch AI providers:', error);
      }
    };
    fetchProviders();
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  const sendMessage = async (content: string) => {
    if (!content.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: content.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    setShowQuickActions(false);

    // Create placeholder for assistant response
    const assistantId = (Date.now() + 1).toString();
    const assistantMessage: Message = {
      id: assistantId,
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      isStreaming: true,
    };
    setMessages((prev) => [...prev, assistantMessage]);

    try {
      // Build history for API
      const history = messages.slice(-10).map((m) => ({
        role: m.role,
        content: m.content,
      }));

      // Use streaming endpoint
      const response = await fetch('/api/v1/ai/chat/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: content,
          history,
          scan_id: scanId,
          provider: selectedProvider,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to get AI response');
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      let fullContent = '';

      while (reader) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ') && line !== 'data: [DONE]') {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.content) {
                fullContent += data.content;
                setMessages((prev) =>
                  prev.map((m) =>
                    m.id === assistantId
                      ? { ...m, content: fullContent }
                      : m
                  )
                );
              } else if (data.error) {
                throw new Error(data.error);
              }
            } catch (e) {
              // Skip parse errors for incomplete chunks
            }
          }
        }
      }

      // Mark as complete
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? { ...m, isStreaming: false }
            : m
        )
      );
    } catch (error) {
      console.error('AI chat error:', error);
      setMessages((prev) =>
        prev.map((m) =>
          m.id === assistantId
            ? {
                ...m,
                content: 'Sorry, I encountered an error. Please check your AI provider configuration or try again.',
                isStreaming: false,
              }
            : m
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const copyToClipboard = (content: string, id: string) => {
    navigator.clipboard.writeText(content);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const clearChat = () => {
    setMessages([]);
    setShowQuickActions(true);
  };

  const configuredProviders = providers.filter((p) => p.configured);

  return (
    <>
      {/* Floating Action Button */}
      <Tooltip title="AI Security Assistant" placement="left">
        <Fab
          color="primary"
          onClick={() => setOpen(true)}
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 1000,
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            '&:hover': {
              background: 'linear-gradient(135deg, #5a6fd6 0%, #6a4190 100%)',
            },
          }}
        >
          <AIIcon />
        </Fab>
      </Tooltip>

      {/* Chat Drawer */}
      <Drawer
        anchor="right"
        open={open}
        onClose={() => setOpen(false)}
        PaperProps={{
          sx: {
            width: { xs: '100%', sm: 420 },
            maxWidth: '100%',
          },
        }}
      >
        {/* Header */}
        <Box
          sx={{
            p: 2,
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: 'white',
          }}
        >
          <Stack direction="row" justifyContent="space-between" alignItems="center">
            <Stack direction="row" spacing={1} alignItems="center">
              <AIIcon />
              <Box>
                <Typography variant="h6" fontWeight="bold">
                  AI Assistant
                </Typography>
                <Typography variant="caption" sx={{ opacity: 0.9 }}>
                  Security Analysis & Guidance
                </Typography>
              </Box>
            </Stack>
            <Stack direction="row" spacing={0.5}>
              <IconButton size="small" onClick={clearChat} sx={{ color: 'white' }}>
                <RefreshIcon fontSize="small" />
              </IconButton>
              <IconButton
                size="small"
                onClick={(e) => setProviderMenuAnchor(e.currentTarget)}
                sx={{ color: 'white' }}
              >
                <SettingsIcon fontSize="small" />
              </IconButton>
              <IconButton size="small" onClick={() => setOpen(false)} sx={{ color: 'white' }}>
                <CloseIcon fontSize="small" />
              </IconButton>
            </Stack>
          </Stack>

          {/* Context indicator */}
          {scanContext && (
            <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
              <Chip
                size="small"
                label={scanContext.target}
                sx={{ bgcolor: 'rgba(255,255,255,0.2)', color: 'white' }}
              />
              {scanContext.critical_count ? (
                <Chip
                  size="small"
                  label={`${scanContext.critical_count} critical`}
                  sx={{ bgcolor: 'error.main', color: 'white' }}
                />
              ) : null}
            </Stack>
          )}
        </Box>

        {/* Provider Menu */}
        <Menu
          anchorEl={providerMenuAnchor}
          open={Boolean(providerMenuAnchor)}
          onClose={() => setProviderMenuAnchor(null)}
        >
          <Typography variant="caption" sx={{ px: 2, py: 1, color: 'text.secondary' }}>
            AI Provider
          </Typography>
          {configuredProviders.length === 0 ? (
            <MenuItem disabled>No providers configured</MenuItem>
          ) : (
            configuredProviders.map((provider) => (
              <MenuItem
                key={provider.id}
                selected={selectedProvider === provider.id}
                onClick={() => {
                  setSelectedProvider(provider.id);
                  setProviderMenuAnchor(null);
                }}
              >
                {provider.name}
                {provider.default && (
                  <Chip label="default" size="small" sx={{ ml: 1 }} />
                )}
              </MenuItem>
            ))
          )}
        </Menu>

        {/* Messages Area */}
        <Box
          sx={{
            flex: 1,
            overflow: 'auto',
            p: 2,
            bgcolor: 'background.default',
            minHeight: 0,
          }}
        >
          {/* Welcome message */}
          {messages.length === 0 && (
            <Box sx={{ textAlign: 'center', py: 4 }}>
              <AIIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                How can I help you?
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                I can analyze vulnerabilities, suggest remediation, and answer security questions.
              </Typography>

              {/* Quick Actions */}
              <Collapse in={showQuickActions && scanId !== undefined}>
                <List>
                  {QUICK_ACTIONS.map((action) => (
                    <ListItem key={action.id} disablePadding>
                      <ListItemButton
                        onClick={() => sendMessage(action.prompt)}
                        sx={{ borderRadius: 2, mb: 0.5 }}
                      >
                        <ListItemIcon>{action.icon}</ListItemIcon>
                        <ListItemText primary={action.label} />
                      </ListItemButton>
                    </ListItem>
                  ))}
                </List>
              </Collapse>
            </Box>
          )}

          {/* Chat messages */}
          {messages.map((message) => (
            <Box
              key={message.id}
              sx={{
                display: 'flex',
                justifyContent: message.role === 'user' ? 'flex-end' : 'flex-start',
                mb: 2,
              }}
            >
              <Paper
                elevation={1}
                sx={{
                  p: 2,
                  maxWidth: '85%',
                  bgcolor: message.role === 'user' ? 'primary.main' : 'background.paper',
                  color: message.role === 'user' ? 'white' : 'text.primary',
                  borderRadius: 2,
                }}
              >
                {message.role === 'assistant' ? (
                  <Box>
                    <ReactMarkdown
                      components={{
                        code({ node, className, children, ...props }) {
                          const match = /language-(\w+)/.exec(className || '');
                          const isInline = !match;
                          return isInline ? (
                            <code
                              style={{
                                background: 'rgba(0,0,0,0.1)',
                                padding: '2px 6px',
                                borderRadius: 4,
                                fontSize: '0.9em',
                              }}
                              {...props}
                            >
                              {children}
                            </code>
                          ) : (
                            <SyntaxHighlighter
                              style={oneDark}
                              language={match[1]}
                              PreTag="div"
                            >
                              {String(children).replace(/\n$/, '')}
                            </SyntaxHighlighter>
                          );
                        },
                      }}
                    >
                      {message.content || (message.isStreaming ? '...' : '')}
                    </ReactMarkdown>

                    {/* Copy button for assistant messages */}
                    {message.content && !message.isStreaming && (
                      <IconButton
                        size="small"
                        onClick={() => copyToClipboard(message.content, message.id)}
                        sx={{ mt: 1 }}
                      >
                        {copiedId === message.id ? (
                          <CheckIcon fontSize="small" color="success" />
                        ) : (
                          <CopyIcon fontSize="small" />
                        )}
                      </IconButton>
                    )}

                    {message.isStreaming && (
                      <CircularProgress size={16} sx={{ ml: 1 }} />
                    )}
                  </Box>
                ) : (
                  <Typography>{message.content}</Typography>
                )}
              </Paper>
            </Box>
          ))}
          <div ref={messagesEndRef} />
        </Box>

        {/* Input Area */}
        <Box sx={{ p: 2, borderTop: 1, borderColor: 'divider' }}>
          <Stack direction="row" spacing={1}>
            <TextField
              inputRef={inputRef}
              fullWidth
              multiline
              maxRows={4}
              placeholder="Ask about vulnerabilities, remediation, or security..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={isLoading || configuredProviders.length === 0}
              size="small"
            />
            <IconButton
              color="primary"
              onClick={() => sendMessage(input)}
              disabled={!input.trim() || isLoading || configuredProviders.length === 0}
            >
              {isLoading ? <CircularProgress size={24} /> : <SendIcon />}
            </IconButton>
          </Stack>

          {configuredProviders.length === 0 && (
            <Typography variant="caption" color="error" sx={{ mt: 1, display: 'block' }}>
              No AI providers configured. Set OPENAI_API_KEY or ANTHROPIC_API_KEY in environment.
            </Typography>
          )}
        </Box>
      </Drawer>
    </>
  );
};

export default AIAssistant;
