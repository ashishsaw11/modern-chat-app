import React, { useState, useEffect, useRef } from 'react';
import { Search, Send, User, MessageCircle, Eye, EyeOff, AlertCircle, RefreshCw, LogOut } from 'lucide-react';
import io from 'socket.io-client';

const API_BASE = process.env.NODE_ENV === 'production' ? '' : 'http://localhost:5000';

// API Service
const API = {
  // Fetch with auth token
  fetchWithAuth: async (url, options = {}) => {
    const token = localStorage.getItem('authToken');
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };
    
    const response = await fetch(`${API_BASE}/api${url}`, config);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Request failed');
    }
    
    return response.json();
  },

  // Get CAPTCHA
  getCaptcha: async () => {
    const response = await fetch(`${API_BASE}/api/captcha`);
    return response.json();
  },

  // Register user
  register: async (username, password, captcha, sessionId) => {
    return API.fetchWithAuth('/register', {
      method: 'POST',
      body: JSON.stringify({ username, password, captcha, sessionId }),
    });
  },

  // Login user
  login: async (username, password, captcha, sessionId) => {
    return API.fetchWithAuth('/login', {
      method: 'POST',
      body: JSON.stringify({ username, password, captcha, sessionId }),
    });
  },

  // Search users
  searchUsers: async (query) => {
    return API.fetchWithAuth(`/users/search?q=${encodeURIComponent(query)}`);
  },

  // Get messages
  getMessages: async (userId) => {
    return API.fetchWithAuth(`/messages/${userId}`);
  },

  // Send message
  sendMessage: async (receiverId, message) => {
    return API.fetchWithAuth('/messages', {
      method: 'POST',
      body: JSON.stringify({ receiverId, message }),
    });
  },

  // Logout
  logout: async () => {
    return API.fetchWithAuth('/logout', { method: 'POST' });
  },
};

const ModernChatApp = () => {
  const [currentUser, setCurrentUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('authToken'));
  const [view, setView] = useState('login');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [socket, setSocket] = useState(null);

  // Auth form states
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // CAPTCHA states
  const [captcha, setCaptcha] = useState('');
  const [captchaInput, setCaptchaInput] = useState('');
  const [sessionId, setSessionId] = useState('');
  const captchaRef = useRef(null);

  // Chat states
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [sendingMessage, setSendingMessage] = useState(false);

  // Initialize socket connection
  useEffect(() => {
    if (currentUser && token) {
      const newSocket = io(API_BASE);
      setSocket(newSocket);
      
      newSocket.emit('join', currentUser.id);
      
      newSocket.on('new_message', (message) => {
        if (activeChat && 
            (message.sender_id === activeChat.id || message.receiver_id === activeChat.id)) {
          setMessages(prev => [...prev, message]);
        }
      });

      return () => {
        newSocket.close();
      };
    }
  }, [currentUser, token, activeChat]);

  // Load CAPTCHA on mount and form changes
  useEffect(() => {
    loadCaptcha();
  }, [view]);

  // Search users effect
  useEffect(() => {
    if (searchTerm.trim() && currentUser && token) {
      const searchUsers = async () => {
        try {
          const results = await API.searchUsers(searchTerm);
          setSearchResults(results);
        } catch (err) {
          console.error('Search failed:', err);
        }
      };
      const debounce = setTimeout(searchUsers, 300);
      return () => clearTimeout(debounce);
    } else {
      setSearchResults([]);
    }
  }, [searchTerm, currentUser, token]);

  // Load messages when active chat changes
  useEffect(() => {
    if (activeChat && currentUser && token) {
      loadMessages();
    }
  }, [activeChat, currentUser, token]);

  // Check for existing token on mount
  useEffect(() => {
    if (token) {
      // In production, verify token with backend
      const userData = JSON.parse(localStorage.getItem('userData') || '{}');
      if (userData.id && userData.username) {
        setCurrentUser(userData);
        setView('chat');
      }
    }
  }, []);

  const loadCaptcha = async () => {
    try {
      const data = await API.getCaptcha();
      setCaptcha(data.captcha);
      setSessionId(data.sessionId);
      drawCaptcha(data.captcha);
    } catch (err) {
      console.error('Failed to load CAPTCHA:', err);
    }
  };

  const drawCaptcha = (captchaText) => {
    if (captchaRef.current) {
      const canvas = captchaRef.current;
      const ctx = canvas.getContext('2d');
      
      // Clear canvas
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      // Background with noise
      const gradient = ctx.createLinearGradient(0, 0, 150, 50);
      gradient.addColorStop(0, 'rgba(99, 102, 241, 0.1)');
      gradient.addColorStop(1, 'rgba(168, 85, 247, 0.1)');
      ctx.fillStyle = gradient;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      
      // Add noise dots
      for (let i = 0; i < 50; i++) {
        ctx.fillStyle = `rgba(${Math.random() * 255}, ${Math.random() * 255}, ${Math.random() * 255}, 0.3)`;
        ctx.fillRect(Math.random() * 150, Math.random() * 50, 2, 2);
      }
      
      // Draw CAPTCHA text
      ctx.font = 'bold 20px Arial';
      ctx.fillStyle = '#4f46e5';
      ctx.textAlign = 'center';
      ctx.fillText(captchaText, 75, 30);
      
      // Add distortion lines
      ctx.strokeStyle = 'rgba(99, 102, 241, 0.3)';
      ctx.lineWidth = 2;
      for (let i = 0; i < 3; i++) {
        ctx.beginPath();
        ctx.moveTo(Math.random() * 150, Math.random() * 50);
        ctx.lineTo(Math.random() * 150, Math.random() * 50);
        ctx.stroke();
      }
    }
  };

  const loadMessages = async () => {
    try {
      const chatMessages = await API.getMessages(activeChat.id);
      setMessages(chatMessages);
    } catch (err) {
      console.error('Failed to load messages:', err);
    }
  };

  const validateForm = () => {
    if (!username.trim() || !password.trim()) {
      setError('Please fill in all fields');
      return false;
    }
    if (!captchaInput.trim()) {
      setError('Please enter CAPTCHA');
      return false;
    }
    return true;
  };

  const handleRegister = async () => {
    if (!validateForm()) return;

    setLoading(true);
    setError('');
    
    try {
      const result = await API.register(username, password, captchaInput, sessionId);
      
      localStorage.setItem('authToken', result.token);
      localStorage.setItem('userData', JSON.stringify(result.user));
      
      setCurrentUser(result.user);
      setToken(result.token);
      setView('chat');
      resetForm();
    } catch (err) {
      setError(err.message);
      loadCaptcha();
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    if (!validateForm()) return;

    setLoading(true);
    setError('');
    
    try {
      const result = await API.login(username, password, captchaInput, sessionId);
      
      localStorage.setItem('authToken', result.token);
      localStorage.setItem('userData', JSON.stringify(result.user));
      
      setCurrentUser(result.user);
      setToken(result.token);
      setView('chat');
      resetForm();
    } catch (err) {
      setError(err.message);
      loadCaptcha();
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setUsername('');
    setPassword('');
    setCaptchaInput('');
    setShowPassword(false);
    loadCaptcha();
  };

  const handleLogout = async () => {
    try {
      if (token) {
        await API.logout();
      }
      
      localStorage.removeItem('authToken');
      localStorage.removeItem('userData');
      
      if (socket) {
        socket.close();
      }
      
      setCurrentUser(null);
      setToken(null);
      setActiveChat(null);
      setView('login');
    } catch (err) {
      console.error('Logout failed:', err);
    }
  };

  const startChat = (user) => {
    setActiveChat(user);
    setSearchTerm('');
    setSearchResults([]);
  };

  const sendMessage = async () => {
    if (!newMessage.trim() || !activeChat || sendingMessage) return;
    
    setSendingMessage(true);
    const messageText = newMessage.trim();
    setNewMessage('');
    
    try {
      const message = await API.sendMessage(activeChat.id, messageText);
      setMessages(prev => [...prev, message]);
    } catch (err) {
      console.error('Failed to send message:', err);
      setNewMessage(messageText);
    } finally {
      setSendingMessage(false);
    }
  };

  const formatTime = (timestamp) => {
    return new Date(timestamp).toLocaleTimeString([], { 
      hour: '2-digit', 
      minute: '2-digit' 
    });
  };

  if (view === 'login' || view === 'register') {
    return (
      <div className="min-h-screen relative overflow-hidden">
        {/* Animated Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-purple-900 via-blue-900 to-indigo-900">
          <div className="absolute inset-0 opacity-20">
            <div className="absolute top-1/4 left-1/4 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl animate-pulse"></div>
            <div className="absolute top-3/4 right-1/4 w-72 h-72 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl animate-pulse animation-delay-2000"></div>
            <div className="absolute bottom-1/4 left-1/2 w-72 h-72 bg-pink-500 rounded-full mix-blend-multiply filter blur-xl animate-pulse animation-delay-4000"></div>
          </div>
        </div>

        <div className="relative z-10 min-h-screen flex items-center justify-center p-4">
          <div className="backdrop-blur-lg bg-white/10 p-8 rounded-3xl shadow-2xl border border-white/20 w-full max-w-md">
            <h2 className="text-4xl font-bold mb-8 text-center text-white">
              {view === 'login' ? 'Welcome Back' : 'Join Us'}
            </h2>
            
            {error && (
              <div className="mb-6 p-4 bg-red-500/20 backdrop-blur-sm border border-red-300/30 rounded-2xl flex items-center text-red-100">
                <AlertCircle className="w-5 h-5 mr-3 flex-shrink-0" />
                <span className="text-sm">{error}</span>
              </div>
            )}
            
            <div className="space-y-6">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full p-4 bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-white placeholder-white/60 transition-all duration-300"
                  disabled={loading}
                />
              </div>
              
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  placeholder={view === 'register' ? "Create password (min 6 chars)" : "Password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && !loading && (view === 'login' ? handleLogin() : handleRegister())}
                  className="w-full p-4 bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-white placeholder-white/60 pr-12 transition-all duration-300"
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-4 text-white/60 hover:text-white transition-colors"
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>

              {/* CAPTCHA */}
              <div className="space-y-3">
                <div className="flex items-center space-x-3">
                  <div className="bg-white/20 backdrop-blur-sm rounded-2xl p-2 border border-white/20">
                    <canvas
                      ref={captchaRef}
                      width="150"
                      height="50"
                      className="rounded-lg"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={loadCaptcha}
                    className="p-3 bg-white/10 backdrop-blur-sm hover:bg-white/20 rounded-xl transition-all duration-300 text-white/80 hover:text-white"
                    disabled={loading}
                  >
                    <RefreshCw className="w-5 h-5" />
                  </button>
                </div>
                <input
                  type="text"
                  placeholder="Enter CAPTCHA"
                  value={captchaInput}
                  onChange={(e) => setCaptchaInput(e.target.value)}
                  className="w-full p-4 bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-white placeholder-white/60 transition-all duration-300"
                  disabled={loading}
                />
              </div>
            </div>
            
            <button
              onClick={view === 'login' ? handleLogin : handleRegister}
              disabled={loading}
              className="w-full mt-8 bg-gradient-to-r from-blue-500 to-purple-600 text-white p-4 rounded-2xl hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-lg transition-all duration-300 transform hover:scale-105 active:scale-95"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
                  {view === 'login' ? 'Signing in...' : 'Creating account...'}
                </div>
              ) : (
                view === 'login' ? 'Sign In' : 'Create Account'
              )}
            </button>
            
            <div className="mt-6 text-center">
              <span className="text-white/80">
                {view === 'login' ? "Don't have an account? " : "Already have an account? "}
              </span>
              <button
                onClick={() => {
                  setView(view === 'login' ? 'register' : 'login');
                  setError('');
                  resetForm();
                }}
                className="text-blue-300 hover:text-blue-200 font-semibold transition-colors"
              >
                {view === 'login' ? 'Sign up' : 'Sign in'}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 flex relative overflow-hidden">
      {/* Background Effects */}
      <div className="absolute inset-0 opacity-30">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500 rounded-full mix-blend-multiply filter blur-xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl animate-pulse animation-delay-2000"></div>
      </div>

      {/* Sidebar */}
      <div className="relative z-10 w-80 backdrop-blur-xl bg-white/5 border-r border-white/10 shadow-2xl">
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">Messages</h2>
            <button
              onClick={handleLogout}
              className="p-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 hover:text-red-200 rounded-xl transition-all duration-300 backdrop-blur-sm"
            >
              <LogOut className="w-5 h-5" />
            </button>
          </div>
          <div className="flex items-center text-white/80 bg-white/10 rounded-2xl p-3 backdrop-blur-sm">
            <User className="w-5 h-5 mr-3 text-blue-300" />
            <span className="font-medium">{currentUser.username}</span>
            <div className="w-2 h-2 bg-green-400 rounded-full ml-auto animate-pulse"></div>
          </div>
        </div>

        <div className="p-6">
          <div className="relative mb-6">
            <Search className="w-5 h-5 absolute left-4 top-4 text-white/40" />
            <input
              type="text"
              placeholder="Search users..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-12 p-4 bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-white placeholder-white/60 transition-all duration-300"
            />
          </div>

          <div className="space-y-3 max-h-96 overflow-y-auto">
            {searchResults.map(user => (
              <div
                key={user.id}
                onClick={() => startChat(user)}
                className={`p-4 rounded-2xl cursor-pointer transition-all duration-300 backdrop-blur-sm ${
                  activeChat?.id === user.id 
                    ? 'bg-blue-500/30 border border-blue-400/50 shadow-lg transform scale-105' 
                    : 'bg-white/5 hover:bg-white/10 hover:transform hover:scale-102 border border-white/10'
                }`}
              >
                <div className="flex items-center">
                  <div className="relative">
                    <div className="w-12 h-12 bg-gradient-to-r from-blue-400 to-purple-500 rounded-full flex items-center justify-center mr-4 shadow-lg">
                      <span className="text-white font-bold text-lg">
                        {user.username.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    {user.isOnline && (
                      <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-white animate-pulse"></div>
                    )}
                  </div>
                  <div>
                    <span className="font-semibold text-white block">{user.username}</span>
                    <span className="text-xs text-white/60">
                      {user.isOnline ? 'Online' : 'Offline'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
            
            {searchTerm && searchResults.length === 0 && (
              <div className="text-center text-white/60 py-8">
                <MessageCircle className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p>No users found</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Chat Area */}
      <div className="relative z-10 flex-1 flex flex-col backdrop-blur-xl bg-white/5">
        {activeChat ? (
          <>
            <div className="p-6 border-b border-white/10 backdrop-blur-xl bg-white/5">
              <div className="flex items-center">
                <div className="relative">
                  <div className="w-12 h-12 bg-gradient-to-r from-blue-400 to-purple-500 rounded-full flex items-center justify-center mr-4 shadow-lg">
                    <span className="text-white font-bold text-lg">
                      {activeChat.username.charAt(0).toUpperCase()}
                    </span>
                  </div>
                  {activeChat.isOnline && (
                    <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-400 rounded-full border-2 border-white animate-pulse"></div>
                  )}
                </div>
                <div>
                  <h3 className="text-xl font-bold text-white">{activeChat.username}</h3>
                  <p className="text-white/60 text-sm">
                    {activeChat.isOnline ? 'Online now' : 'Offline'}
                  </p>
                </div>
              </div>
            </div>

            <div className="flex-1 p-6 overflow-y-auto">
              {messages.length === 0 ? (
                <div className="text-center text-white/60 mt-20">
                  <MessageCircle className="w-20 h-20 mx-auto mb-6 opacity-50" />
                  <p className="text-2xl font-semibold text-white mb-2">Start the conversation</p>
                  <p>Send a message to {activeChat.username}!</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {messages.map(message => (
                    <div
                      key={message.id}
                      className={`flex ${
                        message.sender_id === currentUser.id ? 'justify-end' : 'justify-start'
                      }`}
                    >
                      <div
                        className={`max-w-xs lg:max-w-md px-6 py-4 rounded-3xl shadow-lg backdrop-blur-sm transition-all duration-300 hover:transform hover:scale-105 ${
                          message.sender_id === currentUser.id
                            ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white'
                            : 'bg-white/10 text-white border border-white/20'
                        }`}
                      >
                        <p className="break-words leading-relaxed">{message.message}</p>
                        <p className={`text-xs mt-2 ${
                          message.sender_id === currentUser.id ? 'text-blue-100' : 'text-white/60'
                        }`}>
                          {formatTime(message.timestamp)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="p-6 border-t border-white/10 backdrop-blur-xl bg-white/5">
              <div className="flex space-x-4">
                <input
                  type="text"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && !sendingMessage && sendMessage()}
                  placeholder="Type your message..."
                  className="flex-1 p-4 bg-white/10 backdrop-blur-sm border border-white/20 rounded-2xl focus:ring-2 focus:ring-blue-400 focus:border-transparent text-white placeholder-white/60 transition-all duration-300"
                  disabled={sendingMessage}
                />
                <button
                  onClick={sendMessage}
                  disabled={sendingMessage || !newMessage.trim()}
                  className="bg-gradient-to-r from-blue-500 to-purple-600 text-white p-4 rounded-2xl hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-105 active:scale-95"
                >
                  <Send className="w-6 h-6" />
                </button>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-white/60">
            <div className="text-center">
              <MessageCircle className="w-24 h-24 mx-auto mb-6 opacity-50" />
              <p className="text-3xl font-bold text-white mb-4">Welcome to Modern Chat</p>
              <p className="text-xl">Search for users to start chatting</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ModernChatApp;