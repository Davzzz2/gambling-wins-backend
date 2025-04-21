const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 5000;

// Simple profanity filter
class ProfanityFilter {
  constructor() {
    this.badWords = new Set([
      'nigger',
      'nigga',
      'faggot',
      'retard',
      // Add more words as needed
    ]);
  }

  hasProfanity(text) {
    if (!text) return false;
    const words = text.toLowerCase().split(/\s+/);
    return words.some(word => this.badWords.has(word));
  }

  addWords(...words) {
    words.forEach(word => this.badWords.add(word.toLowerCase()));
  }
}

const filter = new ProfanityFilter();

// Helper function to check text
const checkText = (text) => {
  if (filter.hasProfanity(text)) {
    throw new Error('Text contains inappropriate language');
  }
  return text;
};

// CORS configuration - must be before other middleware
app.use(cors({
  origin: function(origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if(!origin) return callback(null, true);
    
    const allowedOrigins = ['http://localhost:3000', 'https://gambling-wins-frontend.vercel.app'];
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Origin', 'X-Requested-With', 'Accept']
}));

// Middleware
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection with updated options
mongoose.connect("mongodb+srv://DaveAlde:NwTtd7vZp7rNaHOM@cluster0.x5pccae.mongodb.net/gemblewins?retryWrites=true&w=majority&appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
  sslValidate: true,
  retryWrites: true,
  w: 'majority',
  connectTimeoutMS: 30000,
  socketTimeoutMS: 30000
}).then(() => {
  console.log('Connected to MongoDB Atlas successfully');
}).catch((err) => {
  console.error('MongoDB connection error:', err);
});

// Add connection error handler
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

// Add connection success handler
mongoose.connection.once('open', () => {
  console.log('MongoDB connection established successfully');
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  profilePicture: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  joinDate: { type: Date, default: Date.now },
  lastUsernameChange: { type: Date },
});

const winSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  imageUrl: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: String, required: true },
  userProfilePic: { type: String, required: true },
  isEnjayyWin: { type: Boolean, default: false },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  moderatedBy: { type: String },
  moderationDate: { type: Date },
  moderationComment: { type: String },
  kickClipUrl: { type: String }
});

const User = mongoose.model('User', userSchema);
const Win = mongoose.model('Win', winSchema);

// Initialize default users
const initializeUsers = async () => {
  try {
    const users = [
      {
        username: 'admin',
        password: 'admin',
        profilePicture: 'https://ui-avatars.com/api/?name=Admin&background=random',
        role: 'admin'
      },
      {
        username: 'Enjayy',
        password: 'Enjayy',
        profilePicture: 'https://files.kick.com/images/user/1532207/profile_image/conversion/912f3262-98f5-43b5-8b26-ce658fb2f0ba-fullsize.webp',
        role: 'admin'
      },
      {
        username: 'Dave',
        password: 'Dave',
        profilePicture: 'https://cdn.discordapp.com/avatars/1001890926454648935/45f4ad7af60799f281ef9d867df57db5.webp?size=128',
        role: 'admin'
      }
    ];

    for (const user of users) {
      const existingUser = await User.findOne({ username: user.username });
      if (!existingUser) {
        // Create new user with admin role
        const newUser = new User({
          username: user.username,
          password: user.password,
          profilePicture: user.profilePicture,
          role: 'admin' // Explicitly set role to admin
        });
        await newUser.save();
        console.log(`Created admin user: ${user.username}`);
      } else {
        // Update existing user to ensure they have admin role
        existingUser.role = 'admin';
        await existingUser.save();
        console.log(`Updated user ${user.username} to admin role`);
      }
    }
  } catch (error) {
    console.error('Error initializing users:', error);
  }
};

// Call initializeUsers when the server starts
initializeUsers();

// Authentication middleware for admin only
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    
    // Check if user has admin role
    if (user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    
    req.user = user;
    next();
  });
};

// Regular user authentication middleware
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
// Login route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    if (user.password !== password) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create token with user information
    const token = jwt.sign(
      { 
        username: user.username, 
        profilePicture: user.profilePicture,
        role: user.role // Make sure role is included in token
      }, 
      process.env.JWT_SECRET || 'your-secret-key'
    );

    // Send response with user information
    res.json({ 
      token, 
      user: { 
        username: user.username, 
        profilePicture: user.profilePicture,
        role: user.role // Make sure role is included in response
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Create a new win
app.post('/api/wins', authenticateUser, upload.single('image'), async (req, res) => {
  try {
    const { title, description, isEnjayyWin, kickClipUrl } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ message: 'Image is required' });
    }

    // Check for profanity
    try {
      checkText(title);
      checkText(description);
    } catch (error) {
      return res.status(400).json({
        message: 'Your submission contains inappropriate language. Please revise and try again.'
      });
    }

    // For Enjayy's wins, require admin access
    if (isEnjayyWin === 'true' && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required to post Enjayy wins' });
    }

    const win = new Win({
      title,
      description,
      imageUrl: `/uploads/${req.file.filename}`,
      createdBy: req.user.username,
      userProfilePic: req.user.profilePicture,
      isEnjayyWin: isEnjayyWin === 'true',
      kickClipUrl: kickClipUrl || '',
      // Auto-approve if user is admin, regardless of win type
      status: req.user.role === 'admin' ? 'approved' : 'pending'
    });

    await win.save();
    res.status(201).json(win);
  } catch (error) {
    console.error('Error creating win:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get wins with filtering
app.get('/api/wins', async (req, res) => {
  try {
    const { type, status } = req.query;
    
    // Validate query parameters
    if (type && !['enjayy', 'community', 'all'].includes(type)) {
      return res.status(400).json({ 
        message: 'Invalid type parameter. Must be one of: enjayy, community, all' 
      });
    }

    if (status && !['approved', 'pending', 'rejected'].includes(status)) {
      return res.status(400).json({ 
        message: 'Invalid status parameter. Must be one of: approved, pending, rejected' 
      });
    }

    // Build query
    const query = { status: 'approved' };
    
    if (type === 'enjayy') {
      query.isEnjayyWin = true;
    } else if (type === 'community') {
      query.isEnjayyWin = false;
    }

    // Check admin status and handle status filter
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    let isAdmin = false;

    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        isAdmin = decoded.role === 'admin';
        if (status && isAdmin) {
          query.status = status;
        }
      } catch (error) {
        console.error('Token verification error:', error);
        // Don't return error - just continue as non-admin
      }
    }

    // If non-admin tries to filter by status
    if (status && !isAdmin) {
      return res.status(403).json({
        message: 'Only admins can filter by status'
      });
    }

    const wins = await Win.find(query).sort({ createdAt: -1 });

    // No wins found
    if (!wins || wins.length === 0) {
      return res.status(404).json({
        message: 'No wins found matching the criteria'
      });
    }

    res.json(wins);

  } catch (error) {
    console.error('Error fetching wins:', error);
    
    // Handle specific database errors
    if (error.name === 'MongoServerError') {
      return res.status(503).json({ 
        message: 'Database service unavailable. Please try again later.'
      });
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: 'Invalid query parameters',
        details: error.message
      });
    }

    // Generic server error
    res.status(500).json({ 
      message: 'An unexpected error occurred while fetching wins',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Update a win
app.put('/api/wins/:id', authenticateAdmin, upload.single('image'), async (req, res) => {
  try {
    const { title, description } = req.body;
    const updateData = { title, description };
    if (req.file) {
      updateData.imageUrl = `/uploads/${req.file.filename}`;
    }
    const win = await Win.findByIdAndUpdate(req.params.id, updateData, { new: true });
    res.json(win);
  } catch (error) {
    console.error('Error updating win:', error);
    res.status(500).json({ message: error.message });
  }
});

// Delete a win
app.delete('/api/wins/:id', authenticateAdmin, async (req, res) => {
  try {
    await Win.findByIdAndDelete(req.params.id);
    res.json({ message: 'Win deleted successfully' });
  } catch (error) {
    console.error('Error deleting win:', error);
    res.status(500).json({ message: error.message });
  }
});

// Moderation endpoints (admin only)
app.put('/api/wins/:id/moderate', authenticateAdmin, async (req, res) => {
  try {
    const { status, moderationComment } = req.body;
    const win = await Win.findByIdAndUpdate(
      req.params.id,
      {
        status,
        moderationComment,
        moderatedBy: req.user.username,
        moderationDate: new Date()
      },
      { new: true }
    );
    res.json(win);
  } catch (error) {
    console.error('Error moderating win:', error);
    res.status(500).json({ message: error.message });
  }
});

// Get pending submissions (admin only)
app.get('/api/wins/pending', authenticateAdmin, async (req, res) => {
  try {
    const wins = await Win.find({ status: 'pending' }).sort({ createdAt: -1 });
    res.json(wins);
  } catch (error) {
    console.error('Error fetching pending wins:', error);
    res.status(500).json({ message: error.message });
  }
});

// User registration endpoint
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    if (username.length < 3) {
      return res.status(400).json({ message: 'Username must be at least 3 characters long' });
    }

    if (password.length < 4) {
      return res.status(400).json({ message: 'Password must be at least 4 characters long' });
    }

    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Create new user with 'user' role
    const user = new User({
      username,
      password,
      role: 'user',
      profilePicture: `https://ui-avatars.com/api/?name=${encodeURIComponent(username)}&background=random`
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Error registering user' });
  }
});

// Get user profile
app.get('/api/users/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Count user's uploads
    const uploadCount = await Win.countDocuments({ 
      createdBy: username,
      status: 'approved'
    });

    // Get user's recent wins
    const recentWins = await Win.find({ 
      createdBy: username,
      status: 'approved'
    })
    .sort({ createdAt: -1 })
    .limit(6);

    res.json({
      username: user.username,
      profilePicture: user.profilePicture,
      role: user.role,
      joinDate: user.joinDate,
      uploadCount,
      recentWins
    });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ message: error.message });
  }
});

// User settings endpoint
app.get('/api/users/settings', authenticateUser, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      username: user.username,
      profilePicture: user.profilePicture,
      lastUsernameChange: user.lastUsernameChange,
    });
  } catch (error) {
    console.error('Error fetching user settings:', error);
    res.status(500).json({ message: error.message });
  }
});

// Update user settings
app.put('/api/users/settings', authenticateUser, upload.single('profilePicture'), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Handle username change
    if (req.body.username && req.body.username !== user.username) {
      // Check if it's been 30 days since last username change
      if (user.lastUsernameChange) {
        const daysSinceChange = Math.floor((new Date() - user.lastUsernameChange) / (1000 * 60 * 60 * 24));
        if (daysSinceChange < 30) {
          return res.status(400).json({
            message: `You can change your username again in ${30 - daysSinceChange} days`,
          });
        }
      }

      // Check if new username is available
      const existingUser = await User.findOne({ username: req.body.username });
      if (existingUser) {
        return res.status(400).json({ message: 'Username is already taken' });
      }

      user.username = req.body.username;
      user.lastUsernameChange = new Date();
    }

    // Handle profile picture update
    if (req.file) {
      user.profilePicture = `/uploads/${req.file.filename}`;
    }

    await user.save();

    // Create new token with updated user info
    const token = jwt.sign(
      {
        username: user.username,
        profilePicture: user.profilePicture,
        role: user.role,
      },
      process.env.JWT_SECRET || 'your-secret-key'
    );

    res.json({
      token,
      user: {
        username: user.username,
        profilePicture: user.profilePicture,
        role: user.role,
        lastUsernameChange: user.lastUsernameChange
      },
    });
  } catch (error) {
    console.error('Error updating user settings:', error);
    res.status(500).json({ message: error.message });
  }
});

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 
