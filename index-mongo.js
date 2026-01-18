require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'Sync-secret-key-change-in-production';

let db;
let mongoClient;

async function connectDB() {
  try {
    mongoClient = new MongoClient(MONGODB_URI, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      }
    });
    
    await mongoClient.connect();
    db = mongoClient.db('sync');
    
    // Create indexes for better performance
    await db.collection('users').createIndex({ email: 1 }, { unique: true });
    await db.collection('users').createIndex({ username: 1 }, { unique: true, collation: { locale: 'en', strength: 2 } });
    await db.collection('servers').createIndex({ ownerId: 1 });
    await db.collection('channels').createIndex({ serverId: 1 });
    await db.collection('messages').createIndex({ channelId: 1, timestamp: -1 });
    await db.collection('friendRequests').createIndex({ toUserId: 1 });
    await db.collection('friendRequests').createIndex({ fromUserId: 1 });
    
    console.log('Connected to MongoDB!');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

// Initialize Express
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  maxHttpBufferSize: 50 * 1024 * 1024
});

// Middleware
app.use(cors());
app.use(express.json());

// Create uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/uploads', express.static(uploadsDir));

// Configure multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ============ AUTH ROUTES ============

// Check if HWID is already registered
app.get('/api/auth/hwid-check/:hwid', async (req, res) => {
  try {
    const hwid = req.params.hwid;
    
    // Find user by HWID
    const user = await db.collection('users').findOne({ hwid: hwid });
    
    if (user) {
      // Auto-login with HWID
      const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
      
      return res.json({
        exists: true,
        token,
        user: {
          id: user._id,
          username: user.username,
          displayName: user.displayName || user.username,
          email: user.email,
          avatar: user.avatar,
          banner: user.banner,
          bio: user.bio,
          status: 'online',
          customStatus: user.customStatus
        }
      });
    }
    
    res.json({ exists: false });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, hwid } = req.body;
    
    // Check if HWID already has an account
    if (hwid) {
      const hwidUser = await db.collection('users').findOne({ hwid: hwid });
      if (hwidUser) {
        return res.status(400).json({ 
          error: 'This device already has an account registered',
          existingUsername: hwidUser.username
        });
      }
    }
    
    // Check if user exists
    const existingUser = await db.collection('users').findOne({
      $or: [
        { email: email },
        { username: { $regex: new RegExp(`^${username}$`, 'i') } }
      ]
    });
    
    if (existingUser) {
      if (existingUser.email === email) {
        return res.status(400).json({ error: 'Email already registered' });
      }
      return res.status(400).json({ error: 'Username already taken' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    
    const user = {
      _id: userId,
      username,
      displayName: username,
      email,
      password: hashedPassword,
      hwid: hwid || null,
      avatar: null,
      banner: null,
      bio: '',
      status: 'online',
      customStatus: '',
      friends: [],
      createdAt: new Date()
    };
    
    await db.collection('users').insertOne(user);
    
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: userId,
        username,
        displayName: username,
        email,
        avatar: null,
        bio: '',
        status: 'online'
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password, hwid } = req.body;
    
    const user = await db.collection('users').findOne({ email });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // If user doesn't have HWID set, set it now (for existing accounts)
    // Or verify HWID matches if already set
    if (hwid) {
      if (user.hwid && user.hwid !== hwid) {
        return res.status(403).json({ 
          error: 'This account is locked to a different device',
          hint: 'Contact support if you need to transfer your account'
        });
      }
      
      // Set HWID if not already set
      if (!user.hwid) {
        await db.collection('users').updateOne(
          { _id: user._id },
          { $set: { hwid: hwid } }
        );
      }
    }
    
    // Update status
    await db.collection('users').updateOne(
      { _id: user._id },
      { $set: { status: 'online' } }
    );
    
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        displayName: user.displayName || user.username,
        email: user.email,
        avatar: user.avatar,
        banner: user.banner,
        bio: user.bio,
        status: 'online',
        customStatus: user.customStatus
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ USER ROUTES ============

app.get('/api/users/:userId', async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: req.params.userId });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user._id,
      username: user.username,
      displayName: user.displayName || user.username,
      avatar: user.avatar,
      banner: user.banner,
      bio: user.bio || '',
      status: user.status,
      customStatus: user.customStatus || '',
      createdAt: user.createdAt
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:userId', async (req, res) => {
  try {
    const { displayName, bio, customStatus } = req.body;
    
    const result = await db.collection('users').findOneAndUpdate(
      { _id: req.params.userId },
      { $set: { displayName, bio, customStatus } },
      { returnDocument: 'after' }
    );
    
    if (!result) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: result._id,
      username: result.username,
      displayName: result.displayName,
      avatar: result.avatar,
      banner: result.banner,
      bio: result.bio,
      status: result.status,
      customStatus: result.customStatus
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:userId/avatar', upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const avatarPath = `/uploads/${req.file.filename}`;
    
    await db.collection('users').updateOne(
      { _id: req.params.userId },
      { $set: { avatar: avatarPath } }
    );
    
    res.json({ avatar: avatarPath });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:userId/banner', upload.single('banner'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const bannerPath = `/uploads/${req.file.filename}`;
    
    await db.collection('users').updateOne(
      { _id: req.params.userId },
      { $set: { banner: bannerPath } }
    );
    
    res.json({ banner: bannerPath });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Change password
app.post('/api/users/:userId/change-password', async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.params.userId;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password required' });
    }
    
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    const user = await db.collection('users').findOne({ _id: userId });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const validPassword = await bcrypt.compare(currentPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    await db.collection('users').updateOne(
      { _id: userId },
      { $set: { password: hashedPassword } }
    );
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/search', async (req, res) => {
  try {
    const username = req.query.username;
    
    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }
    
    const user = await db.collection('users').findOne({
      username: { $regex: new RegExp(`^${username}$`, 'i') }
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({
      id: user._id,
      username: user.username,
      displayName: user.displayName || user.username,
      avatar: user.avatar,
      status: user.status
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ FRIENDS ROUTES ============

app.get('/api/users/:userId/friends', async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: req.params.userId });
    
    if (!user || !user.friends || user.friends.length === 0) {
      return res.json([]);
    }
    
    const friends = await db.collection('users').find({
      _id: { $in: user.friends }
    }).toArray();
    
    res.json(friends.map(f => ({
      id: f._id,
      username: f.username,
      displayName: f.displayName || f.username,
      avatar: f.avatar,
      status: f.status,
      customStatus: f.customStatus
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/:userId/friend-requests', async (req, res) => {
  try {
    const userId = req.params.userId;
    
    // Get incoming requests
    const incoming = await db.collection('friendRequests').find({
      toUserId: userId,
      status: 'pending'
    }).toArray();
    
    // Get outgoing requests
    const outgoing = await db.collection('friendRequests').find({
      fromUserId: userId,
      status: 'pending'
    }).toArray();
    
    // Get user details for incoming
    const incomingWithUsers = await Promise.all(incoming.map(async (req) => {
      const user = await db.collection('users').findOne({ _id: req.fromUserId });
      return user ? {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar
      } : null;
    }));
    
    // Get user details for outgoing
    const outgoingWithUsers = await Promise.all(outgoing.map(async (req) => {
      const user = await db.collection('users').findOne({ _id: req.toUserId });
      return user ? {
        id: user._id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar
      } : null;
    }));
    
    res.json({
      incoming: incomingWithUsers.filter(u => u !== null),
      outgoing: outgoingWithUsers.filter(u => u !== null)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:userId/friend-request', async (req, res) => {
  try {
    const { targetUserId } = req.body;
    const userId = req.params.userId;
    
    if (targetUserId === userId) {
      return res.status(400).json({ error: "Can't add yourself" });
    }
    
    // Check if already friends
    const user = await db.collection('users').findOne({ _id: userId });
    if (user.friends && user.friends.includes(targetUserId)) {
      return res.status(400).json({ error: 'Already friends' });
    }
    
    // Check for existing request
    const existing = await db.collection('friendRequests').findOne({
      fromUserId: userId,
      toUserId: targetUserId,
      status: 'pending'
    });
    
    if (existing) {
      return res.status(400).json({ error: 'Request already sent' });
    }
    
    // Check if they sent us a request (auto-accept)
    const theirRequest = await db.collection('friendRequests').findOne({
      fromUserId: targetUserId,
      toUserId: userId,
      status: 'pending'
    });
    
    if (theirRequest) {
      // Auto accept
      await db.collection('friendRequests').updateOne(
        { _id: theirRequest._id },
        { $set: { status: 'accepted' } }
      );
      
      // Add to friends lists
      await db.collection('users').updateOne(
        { _id: userId },
        { $addToSet: { friends: targetUserId } }
      );
      await db.collection('users').updateOne(
        { _id: targetUserId },
        { $addToSet: { friends: userId } }
      );
      
      return res.json({ message: 'Friend added!', isFriend: true });
    }
    
    // Create new request
    await db.collection('friendRequests').insertOne({
      _id: uuidv4(),
      fromUserId: userId,
      toUserId: targetUserId,
      status: 'pending',
      createdAt: new Date()
    });
    
    res.json({ message: 'Friend request sent' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:userId/friend-request/accept', async (req, res) => {
  try {
    const { fromUserId } = req.body;
    const userId = req.params.userId;
    
    const request = await db.collection('friendRequests').findOne({
      fromUserId: fromUserId,
      toUserId: userId,
      status: 'pending'
    });
    
    if (!request) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    await db.collection('friendRequests').updateOne(
      { _id: request._id },
      { $set: { status: 'accepted' } }
    );
    
    // Add to friends lists
    await db.collection('users').updateOne(
      { _id: userId },
      { $addToSet: { friends: fromUserId } }
    );
    await db.collection('users').updateOne(
      { _id: fromUserId },
      { $addToSet: { friends: userId } }
    );
    
    res.json({ message: 'Friend request accepted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users/:userId/friend-request/decline', async (req, res) => {
  try {
    const { userId: otherUserId } = req.body;
    const userId = req.params.userId;
    
    // Try to find and delete request (either direction)
    const result = await db.collection('friendRequests').deleteOne({
      $or: [
        { fromUserId: otherUserId, toUserId: userId, status: 'pending' },
        { fromUserId: userId, toUserId: otherUserId, status: 'pending' }
      ]
    });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    
    res.json({ message: 'Request declined' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/:userId/friends/:friendId', async (req, res) => {
  try {
    const { userId, friendId } = req.params;
    
    await db.collection('users').updateOne(
      { _id: userId },
      { $pull: { friends: friendId } }
    );
    await db.collection('users').updateOne(
      { _id: friendId },
      { $pull: { friends: userId } }
    );
    
    res.json({ message: 'Friend removed' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SERVER ROUTES ============

app.get('/api/servers/:userId', async (req, res) => {
  try {
    const servers = await db.collection('servers').find({
      members: req.params.userId
    }).toArray();
    
    res.json(servers.map(s => ({
      id: s._id,
      name: s.name,
      icon: s.icon,
      ownerId: s.ownerId,
      inviteCode: s.inviteCode
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/servers', async (req, res) => {
  try {
    const { name, ownerId } = req.body;
    const serverId = uuidv4();
    const inviteCode = uuidv4().substring(0, 8);
    
    // Default roles with permissions
    const defaultRoles = [
      {
        id: uuidv4(),
        name: '@everyone',
        color: '#99aab5',
        position: 0,
        permissions: {
          viewChannels: true,
          sendMessages: true,
          addReactions: true,
          joinVoice: true,
          speak: true,
          manageMessages: false,
          manageChannels: false,
          manageRoles: false,
          kickMembers: false,
          banMembers: false,
          administrator: false
        }
      },
      {
        id: uuidv4(),
        name: 'Admin',
        color: '#f04747',
        position: 1,
        permissions: {
          viewChannels: true,
          sendMessages: true,
          addReactions: true,
          joinVoice: true,
          speak: true,
          manageMessages: true,
          manageChannels: true,
          manageRoles: true,
          kickMembers: true,
          banMembers: true,
          administrator: true
        }
      }
    ];
    
    const server = {
      _id: serverId,
      name,
      ownerId,
      icon: null,
      inviteCode,
      members: [{
        id: ownerId,
        roles: [defaultRoles[1].id], // Owner gets admin role
        joinedAt: new Date()
      }],
      roles: defaultRoles,
      bans: [],
      createdAt: new Date()
    };
    
    await db.collection('servers').insertOne(server);
    
    // Create default channels
    const generalChannel = {
      _id: uuidv4(),
      serverId,
      name: 'general',
      type: 'text',
      permissionOverwrites: [],
      createdAt: new Date()
    };
    
    const voiceChannel = {
      _id: uuidv4(),
      serverId,
      name: 'Voice Chat',
      type: 'voice',
      permissionOverwrites: [],
      createdAt: new Date()
    };
    
    await db.collection('channels').insertMany([generalChannel, voiceChannel]);
    
    res.json({
      server: {
        id: serverId,
        name,
        icon: null,
        ownerId,
        inviteCode,
        roles: defaultRoles
      },
      channels: [
        { id: generalChannel._id, name: 'general', type: 'text' },
        { id: voiceChannel._id, name: 'Voice Chat', type: 'voice' }
      ]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/servers/:serverId/channels', async (req, res) => {
  try {
    const channels = await db.collection('channels').find({
      serverId: req.params.serverId
    }).toArray();
    
    res.json(channels.map(c => ({
      id: c._id,
      serverId: c.serverId,
      name: c.name,
      type: c.type
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/channels', async (req, res) => {
  try {
    const { serverId, name, type } = req.body;
    const channelId = uuidv4();
    
    const channel = {
      _id: channelId,
      serverId,
      name,
      type: type || 'text',
      createdAt: new Date()
    };
    
    await db.collection('channels').insertOne(channel);
    
    res.json({
      id: channelId,
      serverId,
      name,
      type: type || 'text'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/channels/:channelId/messages', async (req, res) => {
  try {
    const messages = await db.collection('messages')
      .find({ channelId: req.params.channelId })
      .sort({ timestamp: 1 })
      .limit(100)
      .toArray();
    
    res.json(messages.map(m => ({
      id: m._id,
      channelId: m.channelId,
      userId: m.userId,
      username: m.username,
      avatar: m.avatar,
      content: m.content,
      attachments: m.attachments,
      timestamp: m.timestamp
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/invite/:code', async (req, res) => {
  try {
    const server = await db.collection('servers').findOne({
      inviteCode: req.params.code
    });
    
    if (!server) {
      return res.status(404).json({ error: 'Invalid invite code' });
    }
    
    res.json({
      id: server._id,
      name: server.name,
      icon: server.icon,
      memberCount: server.members.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/invite/:code/join', async (req, res) => {
  try {
    const { userId } = req.body;
    
    const server = await db.collection('servers').findOne({
      inviteCode: req.params.code
    });
    
    if (!server) {
      return res.status(404).json({ error: 'Invalid invite code' });
    }
    
    // Check if banned
    if (server.bans && server.bans.some(b => b.id === userId)) {
      return res.status(403).json({ error: 'You are banned from this server' });
    }
    
    // Check if already a member (handle both old and new member format)
    const isMember = server.members.some(m => 
      typeof m === 'string' ? m === userId : m.id === userId
    );
    
    if (isMember) {
      return res.status(400).json({ error: 'Already a member' });
    }
    
    // Get @everyone role id
    const everyoneRole = server.roles?.find(r => r.name === '@everyone');
    
    await db.collection('servers').updateOne(
      { _id: server._id },
      { $addToSet: { members: {
        id: userId,
        roles: everyoneRole ? [] : [], // Everyone role is implicit
        joinedAt: new Date()
      } } }
    );
    
    res.json({
      server: {
        id: server._id,
        name: server.name,
        icon: server.icon,
        ownerId: server.ownerId,
        inviteCode: server.inviteCode,
        roles: server.roles || []
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ PERMISSION HELPER ============
async function getMemberPermissions(serverId, userId) {
  const server = await db.collection('servers').findOne({ _id: serverId });
  if (!server) return null;
  
  // Owner has all permissions
  if (server.ownerId === userId) {
    return {
      viewChannels: true, sendMessages: true, addReactions: true,
      joinVoice: true, speak: true, manageMessages: true,
      manageChannels: true, manageRoles: true, kickMembers: true,
      banMembers: true, administrator: true, isOwner: true
    };
  }
  
  // Find member
  const member = server.members.find(m => 
    typeof m === 'string' ? m === userId : m.id === userId
  );
  if (!member) return null;
  
  // Get @everyone permissions as base
  const everyoneRole = server.roles?.find(r => r.name === '@everyone');
  let permissions = { ...(everyoneRole?.permissions || {}) };
  
  // Add permissions from member's roles
  const memberRoles = typeof member === 'string' ? [] : (member.roles || []);
  for (const roleId of memberRoles) {
    const role = server.roles?.find(r => r.id === roleId);
    if (role) {
      // If admin, grant all permissions
      if (role.permissions.administrator) {
        return {
          viewChannels: true, sendMessages: true, addReactions: true,
          joinVoice: true, speak: true, manageMessages: true,
          manageChannels: true, manageRoles: true, kickMembers: true,
          banMembers: true, administrator: true
        };
      }
      // Merge permissions (true overrides false)
      for (const [key, value] of Object.entries(role.permissions)) {
        if (value) permissions[key] = true;
      }
    }
  }
  
  return permissions;
}

// ============ ROLES API ============
// Get server roles
app.get('/api/servers/:serverId/roles', async (req, res) => {
  try {
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    res.json({ roles: server.roles || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Create role
app.post('/api/servers/:serverId/roles', async (req, res) => {
  try {
    const { userId, name, color, permissions } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.manageRoles && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage roles' });
    }
    
    const newRole = {
      id: uuidv4(),
      name: name || 'New Role',
      color: color || '#99aab5',
      position: (server.roles?.length || 0),
      permissions: permissions || {
        viewChannels: true, sendMessages: true, addReactions: true,
        joinVoice: true, speak: true, manageMessages: false,
        manageChannels: false, manageRoles: false, kickMembers: false,
        banMembers: false, administrator: false
      }
    };
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $push: { roles: newRole } }
    );
    
    res.json({ role: newRole });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update role
app.put('/api/servers/:serverId/roles/:roleId', async (req, res) => {
  try {
    const { userId, name, color, permissions } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.manageRoles && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage roles' });
    }
    
    const roleIndex = server.roles.findIndex(r => r.id === req.params.roleId);
    if (roleIndex === -1) return res.status(404).json({ error: 'Role not found' });
    
    // Can't edit @everyone name
    if (server.roles[roleIndex].name === '@everyone') {
      await db.collection('servers').updateOne(
        { _id: req.params.serverId, 'roles.id': req.params.roleId },
        { $set: { 'roles.$.permissions': permissions, 'roles.$.color': color } }
      );
    } else {
      await db.collection('servers').updateOne(
        { _id: req.params.serverId, 'roles.id': req.params.roleId },
        { $set: { 'roles.$.name': name, 'roles.$.color': color, 'roles.$.permissions': permissions } }
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete role
app.delete('/api/servers/:serverId/roles/:roleId', async (req, res) => {
  try {
    const { userId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.manageRoles && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage roles' });
    }
    
    const role = server.roles.find(r => r.id === req.params.roleId);
    if (!role) return res.status(404).json({ error: 'Role not found' });
    if (role.name === '@everyone') return res.status(400).json({ error: 'Cannot delete @everyone role' });
    
    // Remove role from server and from all members
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { 
        $pull: { roles: { id: req.params.roleId } },
        $set: { 'members.$[].roles': { $pull: req.params.roleId } }
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Assign role to member
app.post('/api/servers/:serverId/members/:memberId/roles', async (req, res) => {
  try {
    const { userId, roleId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.manageRoles && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage roles' });
    }
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId, 'members.id': req.params.memberId },
      { $addToSet: { 'members.$.roles': roleId } }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Remove role from member
app.delete('/api/servers/:serverId/members/:memberId/roles/:roleId', async (req, res) => {
  try {
    const { userId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.manageRoles && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage roles' });
    }
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId, 'members.id': req.params.memberId },
      { $pull: { 'members.$.roles': req.params.roleId } }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ KICK/BAN API ============
// Kick member
app.post('/api/servers/:serverId/kick', async (req, res) => {
  try {
    const { userId, targetId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    // Can't kick owner
    if (targetId === server.ownerId) {
      return res.status(400).json({ error: 'Cannot kick server owner' });
    }
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.kickMembers && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to kick members' });
    }
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $pull: { members: { id: targetId } } }
    );
    
    // Also handle old string format
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $pull: { members: targetId } }
    );
    
    // Notify via socket
    io.emit('member-kicked', { serverId: req.params.serverId, userId: targetId });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Ban member
app.post('/api/servers/:serverId/ban', async (req, res) => {
  try {
    const { userId, targetId, reason } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    // Can't ban owner
    if (targetId === server.ownerId) {
      return res.status(400).json({ error: 'Cannot ban server owner' });
    }
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.banMembers && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to ban members' });
    }
    
    // Remove from members and add to bans
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { 
        $pull: { members: { id: targetId } },
        $addToSet: { bans: { id: targetId, reason: reason || 'No reason provided', bannedAt: new Date() } }
      }
    );
    
    // Also handle old string format
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $pull: { members: targetId } }
    );
    
    // Notify via socket
    io.emit('member-banned', { serverId: req.params.serverId, userId: targetId });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Unban member
app.post('/api/servers/:serverId/unban', async (req, res) => {
  try {
    const { userId, targetId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.banMembers && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to manage bans' });
    }
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $pull: { bans: { id: targetId } } }
    );
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get bans
app.get('/api/servers/:serverId/bans', async (req, res) => {
  try {
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    // Get user info for each ban
    const bans = server.bans || [];
    const bansWithInfo = await Promise.all(bans.map(async (ban) => {
      const user = await db.collection('users').findOne({ _id: ban.id });
      return {
        ...ban,
        username: user?.username || 'Unknown User',
        avatar: user?.avatar
      };
    }));
    
    res.json({ bans: bansWithInfo });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ MESSAGE MANAGEMENT ============
// Delete message
app.delete('/api/messages/:messageId', async (req, res) => {
  try {
    const { userId, serverId } = req.body;
    const message = await db.collection('messages').findOne({ _id: req.params.messageId });
    
    if (!message) return res.status(404).json({ error: 'Message not found' });
    
    // Check if user can delete: own message OR has manageMessages permission
    const isOwnMessage = message.userId === userId;
    let canDelete = isOwnMessage;
    
    if (!isOwnMessage && serverId) {
      const perms = await getMemberPermissions(serverId, userId);
      canDelete = perms?.manageMessages || perms?.isOwner;
    }
    
    if (!canDelete) {
      return res.status(403).json({ error: 'No permission to delete this message' });
    }
    
    await db.collection('messages').deleteOne({ _id: req.params.messageId });
    
    // Notify clients
    io.to(`channel:${message.channelId}`).emit('message-deleted', { 
      messageId: req.params.messageId,
      channelId: message.channelId
    });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add reaction
app.post('/api/messages/:messageId/reactions', async (req, res) => {
  try {
    const { userId, emoji, username } = req.body;
    const message = await db.collection('messages').findOne({ _id: req.params.messageId });
    
    if (!message) return res.status(404).json({ error: 'Message not found' });
    
    // Initialize reactions array if needed
    if (!message.reactions) {
      await db.collection('messages').updateOne(
        { _id: req.params.messageId },
        { $set: { reactions: [] } }
      );
    }
    
    // Check if reaction exists
    const existingReaction = message.reactions?.find(r => r.emoji === emoji);
    
    if (existingReaction) {
      // Add user to existing reaction if not already there
      if (!existingReaction.users.some(u => u.id === userId)) {
        await db.collection('messages').updateOne(
          { _id: req.params.messageId, 'reactions.emoji': emoji },
          { $push: { 'reactions.$.users': { id: userId, username } } }
        );
      }
    } else {
      // Create new reaction
      await db.collection('messages').updateOne(
        { _id: req.params.messageId },
        { $push: { reactions: { emoji, users: [{ id: userId, username }] } } }
      );
    }
    
    // Fetch updated message and broadcast
    const updatedMessage = await db.collection('messages').findOne({ _id: req.params.messageId });
    io.to(`channel:${message.channelId}`).emit('reaction-added', {
      messageId: req.params.messageId,
      channelId: message.channelId,
      reactions: updatedMessage.reactions
    });
    
    res.json({ success: true, reactions: updatedMessage.reactions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Remove reaction
app.delete('/api/messages/:messageId/reactions', async (req, res) => {
  try {
    const { userId, emoji } = req.body;
    const message = await db.collection('messages').findOne({ _id: req.params.messageId });
    
    if (!message) return res.status(404).json({ error: 'Message not found' });
    
    // Remove user from reaction
    await db.collection('messages').updateOne(
      { _id: req.params.messageId, 'reactions.emoji': emoji },
      { $pull: { 'reactions.$.users': { id: userId } } }
    );
    
    // Clean up empty reactions
    await db.collection('messages').updateOne(
      { _id: req.params.messageId },
      { $pull: { reactions: { users: { $size: 0 } } } }
    );
    
    // Fetch updated message and broadcast
    const updatedMessage = await db.collection('messages').findOne({ _id: req.params.messageId });
    io.to(`channel:${message.channelId}`).emit('reaction-removed', {
      messageId: req.params.messageId,
      channelId: message.channelId,
      reactions: updatedMessage.reactions || []
    });
    
    res.json({ success: true, reactions: updatedMessage.reactions || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ SERVER SETTINGS (Icon, etc) ============
// Update server icon
app.put('/api/servers/:serverId/icon', upload.single('icon'), async (req, res) => {
  try {
    const { userId } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.administrator && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to update server settings' });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    const iconUrl = `/uploads/${req.file.filename}`;
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $set: { icon: iconUrl } }
    );
    
    // Notify all members
    io.emit('server-updated', { serverId: req.params.serverId, icon: iconUrl });
    
    res.json({ success: true, icon: iconUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update server name
app.put('/api/servers/:serverId/name', async (req, res) => {
  try {
    const { userId, name } = req.body;
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const userPerms = await getMemberPermissions(req.params.serverId, userId);
    if (!userPerms?.administrator && !userPerms?.isOwner) {
      return res.status(403).json({ error: 'No permission to update server settings' });
    }
    
    await db.collection('servers').updateOne(
      { _id: req.params.serverId },
      { $set: { name } }
    );
    
    io.emit('server-updated', { serverId: req.params.serverId, name });
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user permissions in server
app.get('/api/servers/:serverId/permissions/:userId', async (req, res) => {
  try {
    const permissions = await getMemberPermissions(req.params.serverId, req.params.userId);
    if (!permissions) {
      return res.status(404).json({ error: 'Member not found' });
    }
    res.json({ permissions });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get server members with roles
app.get('/api/servers/:serverId/members', async (req, res) => {
  try {
    const server = await db.collection('servers').findOne({ _id: req.params.serverId });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    // Get full user info for each member
    const membersWithInfo = await Promise.all(server.members.map(async (m) => {
      const memberId = typeof m === 'string' ? m : m.id;
      const user = await db.collection('users').findOne({ _id: memberId });
      return {
        id: memberId,
        username: user?.username || 'Unknown',
        displayName: user?.displayName || user?.username || 'Unknown',
        avatar: user?.avatar,
        roles: typeof m === 'string' ? [] : (m.roles || []),
        joinedAt: m.joinedAt || server.createdAt,
        isOwner: memberId === server.ownerId
      };
    }));
    
    res.json({ members: membersWithInfo, roles: server.roles || [] });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/servers/:serverId/invite', async (req, res) => {
  try {
    const server = await db.collection('servers').findOne({
      _id: req.params.serverId
    });
    
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }
    
    res.json({ inviteCode: server.inviteCode });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// File upload
app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  
  res.json({
    url: `/uploads/${req.file.filename}`,
    filename: req.file.filename,
    originalName: req.file.originalname,
    mimetype: req.file.mimetype,
    size: req.file.size
  });
});

// ============ SOCKET.IO ============

const onlineUsers = new Map();
const userSockets = new Map();

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);
  
  socket.on('authenticate', async ({ userId, username, avatar }) => {
    // Fetch user data from DB to get current avatar
    let userAvatar = avatar;
    try {
      const user = await db.collection('users').findOne({ _id: userId });
      if (user) {
        userAvatar = user.avatar;
      }
    } catch (e) {
      console.error('Error fetching user for socket:', e);
    }
    
    onlineUsers.set(socket.id, { id: userId, username, avatar: userAvatar });
    userSockets.set(userId, socket.id);
    
    io.emit('user-online', { userId, username, avatar: userAvatar });
    
    const onlineList = Array.from(onlineUsers.values());
    socket.emit('online-users', onlineList);
  });
  
  socket.on('join-server', (serverId) => {
    socket.join(`server:${serverId}`);
  });
  
  socket.on('join-channel', (channelId) => {
    socket.join(`channel:${channelId}`);
  });
  
  socket.on('leave-channel', (channelId) => {
    socket.leave(`channel:${channelId}`);
  });
  
  socket.on('send-message', async (data) => {
    const { channelId, message, user, attachments } = data;
    
    const messageData = {
      _id: uuidv4(),
      channelId,
      userId: user.id,
      username: user.username,
      avatar: user.avatar,
      content: message,
      attachments: attachments || [],
      timestamp: new Date()
    };
    
    // Store in MongoDB
    await db.collection('messages').insertOne(messageData);
    
    // Broadcast
    io.to(`channel:${channelId}`).emit('new-message', {
      id: messageData._id,
      channelId: messageData.channelId,
      userId: messageData.userId,
      username: messageData.username,
      avatar: messageData.avatar,
      content: messageData.content,
      attachments: messageData.attachments,
      timestamp: messageData.timestamp
    });
  });
  
  socket.on('typing-start', (data) => {
    socket.to(`channel:${data.channelId}`).emit('user-typing', data);
  });
  
  socket.on('typing-stop', (data) => {
    socket.to(`channel:${data.channelId}`).emit('user-stopped-typing', data);
  });
  
  // Voice channel events
  socket.on('join-voice', (data) => {
    const { channelId, user } = data;
    socket.join(`voice:${channelId}`);
    socket.to(`voice:${channelId}`).emit('user-joined-voice', { user });
    
    const voiceUsers = [];
    const room = io.sockets.adapter.rooms.get(`voice:${channelId}`);
    if (room) {
      for (const socketId of room) {
        const userData = onlineUsers.get(socketId);
        if (userData && userData.id !== user.id) {
          voiceUsers.push(userData);
        }
      }
    }
    socket.emit('voice-channel-users', { users: voiceUsers });
  });
  
  socket.on('leave-voice', (data) => {
    const { channelId, user } = data;
    socket.leave(`voice:${channelId}`);
    socket.to(`voice:${channelId}`).emit('user-left-voice', { user });
  });
  
  socket.on('webrtc-offer', (data) => {
    const targetSocket = userSockets.get(data.targetUserId);
    if (targetSocket) {
      io.to(targetSocket).emit('webrtc-offer', {
        offer: data.offer,
        senderId: data.senderId,
        senderUsername: data.senderUsername
      });
    }
  });
  
  socket.on('webrtc-answer', (data) => {
    const targetSocket = userSockets.get(data.targetUserId);
    if (targetSocket) {
      io.to(targetSocket).emit('webrtc-answer', {
        answer: data.answer,
        senderId: data.senderId
      });
    }
  });
  
  socket.on('webrtc-ice-candidate', (data) => {
    const targetSocket = userSockets.get(data.targetUserId);
    if (targetSocket) {
      io.to(targetSocket).emit('webrtc-ice-candidate', {
        candidate: data.candidate,
        senderId: data.senderId
      });
    }
  });
  
  socket.on('screen-share-start', (data) => {
    socket.to(`voice:${data.channelId}`).emit('user-screen-sharing', { user: data.user });
  });
  
  socket.on('screen-share-stop', (data) => {
    socket.to(`voice:${data.channelId}`).emit('user-stopped-screen-sharing', { user: data.user });
  });
  
  socket.on('disconnect', () => {
    const user = onlineUsers.get(socket.id);
    if (user) {
      userSockets.delete(user.id);
      io.emit('user-offline', { userId: user.id });
    }
    onlineUsers.delete(socket.id);
    console.log('User disconnected:', socket.id);
  });
});

// ============ DIRECT MESSAGES API ============
// Create or get DM channel
app.post('/api/dms', async (req, res) => {
  try {
    const { userId, targetId } = req.body;
    
    // Check if DM channel already exists
    let dm = await db.collection('dms').findOne({
      participants: { $all: [userId, targetId] }
    });
    
    if (!dm) {
      // Create new DM channel
      dm = {
        _id: generateId(),
        participants: [userId, targetId],
        createdAt: new Date(),
        messages: []
      };
      await db.collection('dms').insertOne(dm);
    }
    
    // Get other user's info
    const otherUser = await db.collection('users').findOne({ _id: targetId });
    
    res.json({
      id: dm._id,
      participants: dm.participants,
      otherUser: otherUser ? {
        id: otherUser._id,
        username: otherUser.username,
        avatar: otherUser.avatar
      } : null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user's DM channels
app.get('/api/users/:userId/dms', async (req, res) => {
  try {
    const dms = await db.collection('dms').find({
      participants: req.params.userId
    }).toArray();
    
    // Get other user info for each DM
    const dmsWithUsers = await Promise.all(dms.map(async (dm) => {
      const otherId = dm.participants.find(p => p !== req.params.userId);
      const otherUser = await db.collection('users').findOne({ _id: otherId });
      return {
        id: dm._id,
        otherUser: otherUser ? {
          id: otherUser._id,
          username: otherUser.username,
          avatar: otherUser.avatar
        } : null,
        lastMessage: dm.messages?.[dm.messages.length - 1] || null
      };
    }));
    
    res.json(dmsWithUsers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
  server.listen(PORT, () => {
    console.log(`Sync server running on port ${PORT}`);
  });
});

// Graceful shutdown
process.on('SIGINT', async () => {
  if (mongoClient) {
    await mongoClient.close();
  }
  process.exit(0);
});
