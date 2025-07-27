const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// FIXED: Change default port to 10000 for Render
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const NODE_ENV = process.env.NODE_ENV || 'development';

// CORS configuration for Render
const corsOptions = {
  origin: NODE_ENV === 'production' 
    ? function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        // Allow render.com domains and your custom domain
        if (origin.includes('.onrender.com') || origin.includes('localhost')) {
          return callback(null, true);
        }
        callback(new Error('Not allowed by CORS'));
      }
    : ['http://localhost:3000', 'http://localhost:5000', 'http://localhost:10000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

// Socket.io configuration for Render
const io = socketIo(server, {
  cors: {
    origin: NODE_ENV === 'production' 
      ? function (origin, callback) {
          if (!origin || origin.includes('.onrender.com') || origin.includes('localhost')) {
            return callback(null, true);
          }
          callback(new Error('Not allowed by CORS'));
        }
      : ["http://localhost:3000", "http://localhost:10000"],
    methods: ["GET", "POST"],
    credentials: true
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: NODE_ENV === 'production' ? undefined : false
}));
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === 'production' ? 50 : 200, // More restrictive in production
  message: { error: 'Too many requests, please try again later.' }
});
app.use('/api', limiter);

// Health check endpoint for Render
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    port: PORT
  });
});

// Root health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK' });
});

// Initialize SQLite Database
// FIXED: Better database path handling for Render
const dbPath = path.join(__dirname, 'chat.db');
console.log('Database path:', dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('Connected to SQLite database at:', dbPath);
    initializeDatabase();
  }
});

// Create tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_online INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users (id),
      FOREIGN KEY (receiver_id) REFERENCES users (id)
    )`);

    console.log('Database tables initialized');
  });
}

// Simple CAPTCHA generator
function generateCaptcha() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let result = '';
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Store CAPTCHA sessions in memory (use Redis in production for multiple instances)
const captchaSessions = new Map();

// Clean up old CAPTCHA sessions every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [sessionId, data] of captchaSessions.entries()) {
    if (now - data.timestamp > 10 * 60 * 1000) { // 10 minutes
      captchaSessions.delete(sessionId);
    }
  }
}, 10 * 60 * 1000);

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// API Routes

// Generate CAPTCHA
app.get('/api/captcha', (req, res) => {
  try {
    const captcha = generateCaptcha();
    const sessionId = Math.random().toString(36).substr(2, 15);
    
    captchaSessions.set(sessionId, { 
      captcha, 
      timestamp: Date.now() 
    });
    
    res.json({ captcha, sessionId });
  } catch (error) {
    console.error('CAPTCHA generation error:', error);
    res.status(500).json({ error: 'Failed to generate CAPTCHA' });
  }
});

// Verify CAPTCHA
function verifyCaptcha(sessionId, userInput) {
  const data = captchaSessions.get(sessionId);
  if (!data) return false;
  
  captchaSessions.delete(sessionId); // Use once
  return data.captcha.toLowerCase() === userInput.toLowerCase();
}

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, captcha, sessionId } = req.body;

    // Validate input
    if (!username || !password || !captcha || !sessionId) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Verify CAPTCHA
    if (!verifyCaptcha(sessionId, captcha)) {
      return res.status(400).json({ error: 'Invalid CAPTCHA' });
    }

    // Check if user exists
    db.get('SELECT id FROM users WHERE username = ?', [username.toLowerCase()], async (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (row) {
        return res.status(400).json({ error: 'Username already exists' });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 12);

      // Insert user
      db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
        [username.trim(), passwordHash], 
        function(err) {
          if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }

          const token = jwt.sign({ 
            id: this.lastID, 
            username: username.trim() 
          }, JWT_SECRET, { expiresIn: '24h' });

          res.status(201).json({
            message: 'User created successfully',
            token,
            user: { id: this.lastID, username: username.trim() }
          });
        });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login user
app.post('/api/login', async (req, res) => {
  try {
    const { username, password, captcha, sessionId } = req.body;

    if (!username || !password || !captcha || !sessionId) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Verify CAPTCHA
    if (!verifyCaptcha(sessionId, captcha)) {
      return res.status(400).json({ error: 'Invalid CAPTCHA' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()], async (err, user) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Update online status
      db.run('UPDATE users SET is_online = 1 WHERE id = ?', [user.id]);

      const token = jwt.sign({ 
        id: user.id, 
        username: user.username 
      }, JWT_SECRET, { expiresIn: '24h' });

      res.json({
        token,
        user: { id: user.id, username: user.username }
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Search users
app.get('/api/users/search', authenticateToken, (req, res) => {
  const { q } = req.query;
  const currentUserId = req.user.id;

  if (!q || q.length < 2) {
    return res.json([]);
  }

  db.all(
    'SELECT id, username, is_online FROM users WHERE username LIKE ? AND id != ? LIMIT 20',
    [`%${q}%`, currentUserId],
    (err, users) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(users.map(user => ({
        id: user.id,
        username: user.username,
        isOnline: user.is_online === 1
      })));
    }
  );
});

// Get messages between two users
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
  const currentUserId = req.user.id;
  const otherUserId = parseInt(req.params.userId);

  if (!otherUserId || isNaN(otherUserId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

  db.all(
    `SELECT m.*, u1.username as sender_username, u2.username as receiver_username 
     FROM messages m
     JOIN users u1 ON m.sender_id = u1.id
     JOIN users u2 ON m.receiver_id = u2.id
     WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
     ORDER BY m.timestamp ASC
     LIMIT 100`,
    [currentUserId, otherUserId, otherUserId, currentUserId],
    (err, messages) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(messages);
    }
  );
});

// Send message
app.post('/api/messages', authenticateToken, (req, res) => {
  const { receiverId, message } = req.body;
  const senderId = req.user.id;

  if (!receiverId || !message || !message.trim()) {
    return res.status(400).json({ error: 'Receiver ID and message are required' });
  }

  if (message.trim().length > 1000) {
    return res.status(400).json({ error: 'Message too long (max 1000 characters)' });
  }

  db.run(
    'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
    [senderId, receiverId, message.trim()],
    function(err) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ error: 'Failed to send message' });
      }

      const newMessage = {
        id: this.lastID,
        sender_id: senderId,
        receiver_id: receiverId,
        message: message.trim(),
        timestamp: new Date().toISOString()
      };

      // Emit to socket for real-time updates
      io.to(`user_${receiverId}`).emit('new_message', newMessage);
      io.to(`user_${senderId}`).emit('new_message', newMessage);

      res.status(201).json(newMessage);
    }
  );
});

// Logout
app.post('/api/logout', authenticateToken, (req, res) => {
  const userId = req.user.id;
  
  db.run('UPDATE users SET is_online = 0 WHERE id = ?', [userId], (err) => {
    if (err) {
      console.error('Error updating user status:', err);
    }
  });
  
  res.json({ message: 'Logged out successfully' });
});

// Socket.io for real-time features
io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('join', (userId) => {
    if (userId) {
      socket.join(`user_${userId}`);
      console.log(`User ${userId} joined room user_${userId}`);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// Handle favicon.ico specifically to prevent 500 errors
app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content, but successful response
});

// Handle robots.txt
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send('User-agent: *\nDisallow: /api/\nAllow: /');
});

// FIXED: Better static file serving for production
if (NODE_ENV === 'production') {
  const clientBuildPath = path.join(__dirname, 'client', 'build');
  
  // Check if client build directory exists
  if (fs.existsSync(clientBuildPath)) {
    console.log('Serving static files from:', clientBuildPath);
    app.use(express.static(clientBuildPath, {
      maxAge: '1d', // Cache static files for 1 day
      setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
          res.setHeader('Cache-Control', 'no-cache');
        }
      }
    }));
    
    // Handle React routing, return all requests to React app
    app.get('*', (req, res) => {
      try {
        res.sendFile(path.join(clientBuildPath, 'index.html'));
      } catch (error) {
        console.error('Error serving index.html:', error);
        res.status(500).json({ error: 'Failed to serve application' });
      }
    });
  } else {
    console.log('Client build directory not found, serving API only');
    
    // Create a simple HTML page for the root route
    app.get('/', (req, res) => {
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Chat API Server</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 600px; margin: 0 auto; }
            .endpoint { background: #f5f5f5; padding: 10px; margin: 5px 0; border-radius: 5px; }
          </style>
        </head>
        <body>
          <div class="container">
            <h1>🚀 Chat API Server</h1>
            <p>The server is running successfully!</p>
            
            <h2>Available API Endpoints:</h2>
            <div class="endpoint">GET /api/health - Server health check</div>
            <div class="endpoint">GET /api/captcha - Generate CAPTCHA</div>
            <div class="endpoint">POST /api/register - Register new user</div>
            <div class="endpoint">POST /api/login - User login</div>
            <div class="endpoint">GET /api/users/search - Search users (requires auth)</div>
            <div class="endpoint">GET /api/messages/:userId - Get messages (requires auth)</div>
            <div class="endpoint">POST /api/messages - Send message (requires auth)</div>
            <div class="endpoint">POST /api/logout - User logout (requires auth)</div>
            
            <h2>Server Info:</h2>
            <p><strong>Environment:</strong> ${NODE_ENV}</p>
            <p><strong>Port:</strong> ${PORT}</p>
            <p><strong>Time:</strong> ${new Date().toISOString()}</p>
          </div>
        </body>
        </html>
      `);
    });
    
    // Handle other non-API routes
    app.get('*', (req, res) => {
      // Don't handle API routes here
      if (req.path.startsWith('/api/')) {
        return;
      }
      
      res.status(404).json({ 
        error: 'Page not found',
        message: 'This is an API-only server. Check the root path for available endpoints.',
        availableEndpoints: ['/api/health', '/api/captcha', '/api/register', '/api/login']
      });
    });
  }
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.stack);
  console.error('Request URL:', req.url);
  console.error('Request Method:', req.method);
  
  // Send appropriate response based on request type
  if (req.xhr || req.headers.accept?.indexOf('json') > -1) {
    res.status(500).json({ error: 'Something went wrong!' });
  } else {
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <head><title>Server Error</title></head>
      <body>
        <h1>500 - Server Error</h1>
        <p>Something went wrong. Please try again later.</p>
        <a href="/">Go to Home</a>
      </body>
      </html>
    `);
  }
});

// Handle 404 for API routes
app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

// Start server - FIXED: Better error handling
server.listen(PORT, '0.0.0.0', (err) => {
  if (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📊 Environment: ${NODE_ENV}`);
  console.log(`🗄️  Database: ${dbPath}`);
  console.log(`🌐 Server accessible at: http://0.0.0.0:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('🛑 Shutting down server...');
  server.close(() => {
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
      } else {
        console.log('✅ Database connection closed');
      }
      process.exit(0);
    });
  });
});

process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  server.close(() => {
    db.close(() => {
      process.exit(0);
    });
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});
