const express = require('express');
const path = require('path');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const fs = require('fs').promises;
const http = require('http');
const socketIo = require('socket.io');
const multer = require('multer');
const { MongoClient, ServerApiVersion } = require('mongodb');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'rovel-secret-key-change-in-production';
const ADMIN_EMAIL = 'wtfziyan@gmail.com';
const ADMIN_PASSWORD = 'xiyan12345';
const MONGODB_URI = process.env.MONGODB_URI || "mongodb+srv://wtfziyan_db_user:ewK0I4dAtsrRDNeI@cluster0.5vavyni.mongodb.net/Rovels?retryWrites=true&w=majority&appName=Cluster0";

const DATA_DIR = './data';
const MANGA_FILE = path.join(DATA_DIR, 'manga.json');
const NOVELS_FILE = path.join(DATA_DIR, 'novels.json');
const CHAPTERS_FILE = path.join(DATA_DIR, 'chapters.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ADS_CONFIG_FILE = path.join(DATA_DIR, 'ads-config.json');
const UNLOCKS_FILE = path.join(DATA_DIR, 'unlocks.json');
const VIEWS_FILE = path.join(DATA_DIR, 'views.json');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const RANK_FILE = path.join(DATA_DIR, 'rank.json');
const SEARCH_FILE = path.join(DATA_DIR, 'search.json');
const ANALYTICS_FILE = path.join(DATA_DIR, 'analytics.json');
const USER_ACTIVITY_FILE = path.join(DATA_DIR, 'user-activity.json');

let mangaData = [];
let novelsData = [];
let chaptersData = {};
let usersData = [];
let adsConfigData = {};
let unlocksData = {};
let viewsData = {};
let configData = {};
let rankData = {};
let searchData = {};
let analyticsData = {};
let userActivityData = {};

let client;
let db;

async function loadData() {
  try {
    if (!db) {
      const connected = await connectToMongoDB();
      if (!connected) {
        console.log('⚠️  Using in-memory data storage due to MongoDB connection failure');
        return;
      }
    }

    // ✅ Simple approach - alag alag await use karo
    const mangaCollection = await db.collection('manga').find({}).toArray();
    const novelsCollection = await db.collection('novels').find({}).toArray();
    const chaptersCollection = await db.collection('chapters').find({}).toArray();
    const usersCollection = await db.collection('users').find({}).toArray();
    const adsConfigCollection = await db.collection('ads-config').findOne({});
    const unlocksCollection = await db.collection('unlocks').findOne({});
    const viewsCollection = await db.collection('views').findOne({});
    const configCollection = await db.collection('config').findOne({});
    const rankCollection = await db.collection('rank').findOne({});
    const searchCollection = await db.collection('search').findOne({});
    const analyticsCollection = await db.collection('analytics').findOne({});
    const userActivityCollection = await db.collection('user-activity').findOne({});

    // Data assign karo
    mangaData = mangaCollection || [];
    novelsData = novelsCollection || [];
    
    chaptersData = {};
    if (chaptersCollection) {
      chaptersCollection.forEach(doc => {
        chaptersData[doc._id] = doc.chapters;
      });
    }
    
    usersData = usersCollection || [];
    adsConfigData = adsConfigCollection || {};
    unlocksData = unlocksCollection || {};
    viewsData = viewsCollection || {};
    configData = configCollection || {};
    rankData = rankCollection || {};
    searchData = searchCollection || {};
    analyticsData = analyticsCollection || {};
    userActivityData = userActivityCollection || {};

    console.log(`✅ Data loaded from MongoDB successfully`);

  } catch (error) {
    console.error(`❌ Error loading data from MongoDB:`, error);
  }

async function saveData(collectionName, data) {
  try {
    if (!db) {
      const connected = await connectToMongoDB();
      if (!connected) return;
    }

    const collection = db.collection(collectionName);
    
    if (Array.isArray(data)) {
      await collection.deleteMany({});
      if (data.length > 0) {
        await collection.insertMany(data);
      }
    } else {
      await collection.deleteMany({});
      await collection.insertOne(data);
    }
  } catch (error) {
    console.error(`❌ Error saving data to MongoDB collection ${collectionName}:`, error);
  }
}

async function saveChaptersData() {
  try {
    if (!db) {
      const connected = await connectToMongoDB();
      if (!connected) return;
    }

    const collection = db.collection('chapters');
    await collection.deleteMany({});
    
    const chaptersArray = Object.entries(chaptersData).map(([mangaId, chapters]) => ({
      _id: mangaId,
      chapters: chapters
    }));
    
    if (chaptersArray.length > 0) {
      await collection.insertMany(chaptersArray);
    }
  } catch (error) {
    console.error(`❌ Error saving chapters data to MongoDB:`, error);
  }
}

function findUserById(id) {
  return usersData.find(user => user._id === id);
}

function findUserByEmail(email) {
  return usersData.find(user => user.email === email);
}

function findUserByDeviceId(deviceId) {
  return usersData.find(user => user.deviceId === deviceId);
}

function findMangaById(id) {
  return mangaData.find(item => item.id === id);
}

function findNovelById(id) {
  return novelsData.find(item => item.id === id);
}

function findChapter(manga, chapterId) {
  const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
  return chaptersData[normalizedTitle]?.[chapterId];
}

async function updateUser(userId, updates) {
  const userIndex = usersData.findIndex(user => user._id === userId);
  if (userIndex !== -1) {
    usersData[userIndex] = { ...usersData[userIndex], ...updates };
    await saveData('users', usersData);
    return usersData[userIndex];
  }
  return null;
}

const userSockets = new Map();
const chapterTimers = new Map();

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = path.join(__dirname, 'data', 'uploads', 'all_img');
    fs.mkdir(uploadDir, { recursive: true }).then(() => {
      cb(null, uploadDir);
    }).catch(err => {
      cb(err, null);
    });
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: function (req, file, cb) {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'data', 'uploads', 'all_img')));

app.use('/api/chapter/*', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

const authenticateToken = async (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];

  if (!token) {
    req.user = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = findUserById(decoded.userId);

    if (!user) {  
      res.clearCookie('token');  
      return res.status(401).json({ error: 'User not found' });  
    }  

    req.user = user;  
    next();

  } catch (error) {
    console.error('Token verification error:', error);
    res.clearCookie('token');
    return res.status(401).json({ error: 'Invalid token' });
  }
};

const requireAuth = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

const requireAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = findUserById(decoded.userId);

    if (!user || user.email !== ADMIN_EMAIL) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    req.admin = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid admin token' });
  }
};

let allPosts = [];

function refreshAllPosts() {
  allPosts = [...mangaData, ...novelsData];
}

async function initializeData() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });

    const files = [  
      { path: MANGA_FILE, default: '[]' },  
      { path: NOVELS_FILE, default: '[]' },  
      { path: CHAPTERS_FILE, default: '{}' },  
      { path: USERS_FILE, default: '[]' },  
      { path: ADS_CONFIG_FILE, default: '{}' },  
      { path: UNLOCKS_FILE, default: '{}' },  
      { path: VIEWS_FILE, default: '{}' },  
      { path: CONFIG_FILE, default: '{"unlockDuration": 40, "validityDuration": 30}' },  
      { path: RANK_FILE, default: '{}' },
      { path: SEARCH_FILE, default: '{"searches": [], "trending": []}' },
      { path: ANALYTICS_FILE, default: '{}' },
      { path: USER_ACTIVITY_FILE, default: '{}' }
    ];  
    
    for (const file of files) {  
      try {  
        await fs.access(file.path);  
      } catch {  
        await fs.writeFile(file.path, file.default);  
      }  
    }  
    
    await loadData();  
    
    await initializeSampleData();  

  } catch (err) {
    console.error(`❌ Error initializing data:`, err);
  }
}

async function initializeSampleData() {
  try {
    const sampleUsers = [  
      {
        "_id": "admin-auto",
        "name": "Admin",
        "email": ADMIN_EMAIL,
        "password": await bcrypt.hash(ADMIN_PASSWORD, 12),
        "role": "admin",
        "createdAt": new Date().toISOString(),
        "lastSeen": new Date().toISOString(),
        "readHistory": [],
        "likedGenres": [],
        "unlockedChapters": [],
        "continueReading": {},
        "likes": [],
        "readLater": [],
        "viewedChapters": [],
        "searchHistory": []
      }
    ];  

    if (usersData.length === 0) {  
      usersData = sampleUsers;  
      await saveData('users', usersData);  
    }  

    refreshAllPosts();

  } catch (err) {
    console.error(`❌ Error initializing sample data:`, err);
  }
}

io.on('connection', (socket) => {
  socket.on('user-authenticated', (userId) => {
    userSockets.set(userId, socket.id);
    socket.join(`user-${userId}`);
  });

  socket.on('disconnect', () => {
    for (const [userId, socketId] of userSockets.entries()) {
      if (socketId === socket.id) {
        userSockets.delete(userId);
        break;
      }
    }
  });
});

function broadcastToUser(userId, event, data) {
  io.to(`user-${userId}`).emit(event, data);
}

function broadcastToAll(event, data) {
  io.emit(event, data);
}

function calculateStats() {
  const totalPosts = mangaData.length + novelsData.length;
  
  let totalChapters = 0;
  Object.values(chaptersData).forEach(mangaChapters => {
    totalChapters += Object.keys(mangaChapters).length;
  });
  
  let totalViews = 0;
  Object.values(chaptersData).forEach(mangaChapters => {
    Object.values(mangaChapters).forEach(chapter => {
      totalViews += chapter.totalViews || 0;
    });
  });

  let totalUnlocks = 0;
  Object.values(chaptersData).forEach(mangaChapters => {
    Object.values(mangaChapters).forEach(chapter => {
      totalUnlocks += chapter.totalUnlocks || 0;
    });
  });

  let totalLikes = 0;
  usersData.forEach(user => {
    totalLikes += user.likes ? user.likes.length : 0;
  });
  
  return {
    totalPosts,
    totalUsers: usersData.length,
    totalChapters,
    totalViews,
    totalUnlocks,
    totalLikes
  };
}

function calculateTimeBasedAnalytics(period) {
  const now = new Date();
  let startDate;

  switch (period) {
    case '48h':
      startDate = new Date(now.getTime() - 48 * 60 * 60 * 1000);
      break;
    case '7d':
      startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      break;
    case '28d':
      startDate = new Date(now.getTime() - 28 * 24 * 60 * 60 * 1000);
      break;
    default:
      startDate = new Date(now.getTime() - 48 * 60 * 60 * 1000);
  }

  let chaptersUnlocked = 0;
  let newAccounts = 0;
  let viewsPerChapter = 0;

  usersData.forEach(user => {
    if (user.unlockedChapters) {
      user.unlockedChapters.forEach(unlock => {
        const unlockedAt = new Date(unlock.unlockedAt);
        if (unlockedAt >= startDate) {
          chaptersUnlocked++;
        }
      });
    }
  });

  usersData.forEach(user => {
    const createdAt = new Date(user.createdAt);
    if (createdAt >= startDate) {
      newAccounts++;
    }
  });

  let totalChapterViews = 0;
  let chaptersWithViews = 0;

  Object.values(chaptersData).forEach(mangaChapters => {
    Object.values(mangaChapters).forEach(chapter => {
      const chapterViews = Math.floor((chapter.totalViews || 0) * 0.1);
      if (chapterViews > 0) {
        totalChapterViews += chapterViews;
        chaptersWithViews++;
      }
    });
  });

  viewsPerChapter = chaptersWithViews > 0 ? Math.round(totalChapterViews / chaptersWithViews) : 0;

  return {
    chaptersUnlocked,
    newAccounts,
    viewsPerChapter
  };
}

function getTopPosts(limit = 5) {
  const allWithViews = [...mangaData, ...novelsData].map(post => {
    const normalizedTitle = post.title.toLowerCase().replace(/\s+/g, '-');
    let postViews = 0;
    
    if (chaptersData[normalizedTitle]) {
      Object.values(chaptersData[normalizedTitle]).forEach(chapter => {
        postViews += chapter.totalViews || 0;
      });
    }
    
    return {
      ...post,
      views: postViews
    };
  });
  
  return allWithViews
    .sort((a, b) => b.views - a.views)
    .slice(0, limit);
}

function getTopSearches(limit = 5) {
  if (!searchData.searches) return [];
  
  const searchCounts = {};
  searchData.searches.forEach(search => {
    searchCounts[search.query] = (searchCounts[search.query] || 0) + 1;
  });
  
  return Object.entries(searchCounts)
    .map(([query, count]) => ({ query, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function getRecentUsers(limit = 5) {
  return usersData
    .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))
    .slice(0, limit);
}

function startChapterTimer(userId, chapterId, manga) {
  const timerKey = `${userId}-${manga}-${chapterId}`;

  const startTime = Date.now();
  const unlockData = {
    userId,
    manga,
    chapterId,
    startTime,
    expectedUnlockTime: startTime + 40000
  };

  if (!unlocksData[timerKey]) {
    unlocksData[timerKey] = [];
  }
  unlocksData[timerKey].push(unlockData);
  saveData('unlocks', unlocksData);

  if (chapterTimers.has(timerKey)) {
    clearTimeout(chapterTimers.get(timerKey));
  }

  const timer = setTimeout(async () => {
    await unlockChapterForUser(userId, manga, chapterId);
    chapterTimers.delete(timerKey);

    if (unlocksData[timerKey]) {  
      delete unlocksData[timerKey];  
      saveData('unlocks', unlocksData);  
    }

  }, 40000);

  chapterTimers.set(timerKey, timer);
  return timerKey;
}

function checkChapterTimer(userId, chapterId, manga) {
  const timerKey = `${userId}-${manga}-${chapterId}`;

  const timer = chapterTimers.get(timerKey);
  if (timer) {
    const unlockData = unlocksData[timerKey]?.[0];
    if (unlockData) {
      const elapsed = Date.now() - unlockData.startTime;
      const secondsLeft = Math.max(0, Math.ceil((40000 - elapsed) / 1000));
      const progress = Math.min(100, Math.floor((elapsed / 40000) * 100));

      return { active: true, secondsLeft, progress };  
    }
  }

  const unlockData = unlocksData[timerKey]?.[0];
  if (unlockData && Date.now() >= unlockData.expectedUnlockTime) {
    unlockChapterForUser(userId, manga, chapterId);
    delete unlocksData[timerKey];
    saveData('unlocks', unlocksData);

    return { active: false, secondsLeft: 0, progress: 100, unlocked: true };
  }

  return { active: false, secondsLeft: 0, progress: 100 };
}

async function unlockChapterForUser(userId, manga, chapterId) {
  const user = findUserById(userId);
  if (!user) return false;

  const validityDuration = 30 * 60 * 1000;
  const expiresAt = new Date(Date.now() + validityDuration);

  if (!user.unlockedChapters) {
    user.unlockedChapters = [];
  }

  user.unlockedChapters = user.unlockedChapters.filter(
    unlock => !(unlock.manga === manga && unlock.chapterId === chapterId)
  );

  user.unlockedChapters.push({
    manga,
    chapterId,
    unlockedAt: new Date().toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
  if (chaptersData[normalizedTitle] && chaptersData[normalizedTitle][chapterId]) {
    chaptersData[normalizedTitle][chapterId].totalUnlocks = 
      (chaptersData[normalizedTitle][chapterId].totalUnlocks || 0) + 1;
  }

  await saveData('users', usersData);
  await saveChaptersData();

  const unlockLog = {
    userId,
    manga,
    chapterId,
    unlockedAt: new Date().toISOString(),
    method: 'timer'
  };

  if (!unlocksData.unlockLogs) {
    unlocksData.unlockLogs = [];
  }
  unlocksData.unlockLogs.push(unlockLog);
  await saveData('unlocks', unlocksData);

  updateAnalytics();

  broadcastToUser(userId, 'chapterUnlocked', { manga, chapterId, expiresAt });

  return true;
}

function lockChapterForUser(userId, manga, chapterId) {
  const user = findUserById(userId);
  if (!user || !user.unlockedChapters) return false;

  const originalLength = user.unlockedChapters.length;
  user.unlockedChapters = user.unlockedChapters.filter(
    unlock => !(unlock.manga === manga && unlock.chapterId === chapterId)
  );

  if (user.unlockedChapters.length !== originalLength) {
    saveData('users', usersData);
    return true;
  }

  return false;
}

function updateAnalytics() {
  const now = new Date();
  const dateKey = now.toISOString().split('T')[0];

  if (!analyticsData[dateKey]) {
    analyticsData[dateKey] = {
      date: dateKey,
      chaptersUnlocked: 0,
      newAccounts: 0,
      totalViews: 0,
      activeUsers: 0
    };
  }

  analyticsData[dateKey].chaptersUnlocked += 1;

  const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
  Object.keys(analyticsData).forEach(key => {
    const analyticsDate = new Date(key);
    if (analyticsDate < ninetyDaysAgo) {
      delete analyticsData[key];
    }
  });

  saveData('analytics', analyticsData);
}

function updateUserActivity(userId, activityType, data) {
  if (!userActivityData[userId]) {
    userActivityData[userId] = {
      userId,
      activities: []
    };
  }

  userActivityData[userId].activities.push({
    type: activityType,
    data,
    timestamp: new Date().toISOString()
  });

  if (userActivityData[userId].activities.length > 100) {
    userActivityData[userId].activities = userActivityData[userId].activities.slice(-100);
  }

  saveData('user-activity', userActivityData);
}

async function calculateRanks() {
  try {
    const rankResults = {};

    allPosts.forEach(post => {  
      const normalizedTitle = post.title.toLowerCase().replace(/\s+/g, '-');  
      let totalViews = 0;  
      let totalUnlocks = 0;  
        
      if (chaptersData[normalizedTitle]) {  
        Object.values(chaptersData[normalizedTitle]).forEach(chapter => {  
          totalViews += chapter.totalViews || 0;  
          totalUnlocks += chapter.totalUnlocks || 0;  
        });  
      }  
        
      let totalLikes = 0;
      usersData.forEach(user => {
        if (user.likes && user.likes.includes(post.id)) {
          totalLikes++;
        }
      });
        
      rankResults[post.id] = {  
        id: post.id,  
        title: post.title,  
        type: post.type,  
        cover: post.cover,  
        author: post.author,
        totalViews: totalViews,  
        totalUnlocks: totalUnlocks,
        totalLikes: totalLikes,
        chaptersCount: post.chapters_count || 0,  
        rating: post.rating || 0  
      };  
    });  
    
    const byViews = Object.values(rankResults)
      .sort((a, b) => b.totalViews - a.totalViews)
      .slice(0, 50);

    const byUnlocks = Object.values(rankResults)
      .sort((a, b) => b.totalUnlocks - a.totalUnlocks)
      .slice(0, 50);

    const byLikes = Object.values(rankResults)
      .sort((a, b) => b.totalLikes - a.totalLikes)
      .slice(0, 50);
    
    rankData = {  
      lastUpdated: new Date().toISOString(),  
      byViews,
      byUnlocks,
      byLikes
    };  
    
    await saveData('rank', rankData);  
    
    return rankData;

  } catch (error) {
    console.error('Error calculating ranks:', error);
    return {};
  }
}

function generateSlug(title) {
  return title.toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9-]/g, '')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

async function updatePostChaptersCount(normalizedTitle) {
  let post = mangaData.find(item => generateSlug(item.title) === normalizedTitle);
  let targetData = mangaData;
  let targetFile = 'manga';

  if (!post) {
    post = novelsData.find(item => generateSlug(item.title) === normalizedTitle);
    targetData = novelsData;
    targetFile = 'novels';
  }

  if (post) {
    const chapters = chaptersData[normalizedTitle] || {};
    const chaptersCount = Object.keys(chapters).length;

    post.chapters_count = chaptersCount;
    post.latest_chapter_id = chaptersCount > 0 ? Math.max(...Object.keys(chapters).map(Number)).toString() : "0";

    await saveData(targetFile, targetData);
  }
}

function applySecurityHeaders(res) {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
}

function isChapterUnlocked(user, manga, chapterId) {
  if (!user || !user.unlockedChapters) return false;

  const now = new Date();
  return user.unlockedChapters.some(unlock => 
    unlock.manga === manga && 
    unlock.chapterId === chapterId && 
    new Date(unlock.expiresAt) > now
  );
}

function validateAdCompletion(userId, manga, chapterId) {
  const timerKey = `${userId}-${manga}-${chapterId}`;
  const timer = chapterTimers.get(timerKey);
  
  return timer !== undefined;
}

function startCleanupInterval() {
  setInterval(async () => {
    try {
      const now = new Date();
      let cleanedCount = 0;

      usersData.forEach(user => {  
        if (user.unlockedChapters) {  
          const originalLength = user.unlockedChapters.length;  
          user.unlockedChapters = user.unlockedChapters.filter(  
            unlock => new Date(unlock.expiresAt) > now  
          );  
          if (user.unlockedChapters.length !== originalLength) {  
            cleanedCount++;  
          }  
        }  
      });  

      if (cleanedCount > 0) {  
        await saveData('users', usersData);  
      }  
    } catch (error) {  
      console.error('Error cleaning up expired unlocks:', error);  
    }
  }, 10 * 60 * 1000);
}

function startRankCalculationInterval() {
  calculateRanks();

  setInterval(() => {
    calculateRanks();
  }, 60 * 60 * 1000);
}

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.role !== 'admin') {
      return res.status(401).json({ error: 'Admin access required' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    user.lastSeen = new Date().toISOString();
    await saveData('users', usersData);

    const token = jwt.sign({ userId: user._id, role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
    
    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      message: 'Admin login successful'
    });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Admin login failed' });
  }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const stats = calculateStats();
    
    const adminStats = {
      ...stats,
      totalManga: mangaData.length,
      totalNovels: novelsData.length,
      totalChapters: Object.values(chaptersData).reduce((acc, chapters) => acc + Object.keys(chapters).length, 0),
      activeUsers: usersData.filter(user => {
        const lastSeen = new Date(user.lastSeen);
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        return lastSeen > thirtyDaysAgo;
      }).length
    };
    
    res.json({
      success: true,
      stats: adminStats
    });
  } catch (error) {
    console.error('Get admin stats error:', error);
    res.status(500).json({ error: 'Failed to get admin stats' });
  }
});

app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  try {
    const { period = '48h' } = req.query;
    
    const analytics = calculateTimeBasedAnalytics(period);
    
    res.json({
      success: true,
      analytics,
      period
    });
  } catch (error) {
    console.error('Get analytics error:', error);
    res.status(500).json({ error: 'Failed to get analytics' });
  }
});

app.get('/api/admin/user-activity', requireAdmin, async (req, res) => {
  try {
    const usersWithActivity = usersData.map(user => {
      const { password, ...userWithoutPassword } = user;
      return userWithoutPassword;
    });
    
    res.json({
      success: true,
      users: usersWithActivity
    });
  } catch (error) {
    console.error('Get user activity error:', error);
    res.status(500).json({ error: 'Failed to get user activity' });
  }
});

app.put('/api/admin/content/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    const postId = parseInt(id);

    let targetData, targetFile;
    let postIndex = mangaData.findIndex(post => post.id === postId);
    
    if (postIndex !== -1) {
      targetData = mangaData;
      targetFile = 'manga';
    } else {
      postIndex = novelsData.findIndex(post => post.id === postId);
      if (postIndex !== -1) {
        targetData = novelsData;
        targetFile = 'novels';
      } else {
        return res.status(404).json({ error: 'Post not found' });
      }
    }

    targetData[postIndex] = { ...targetData[postIndex], ...updates };
    await saveData(targetFile, targetData);
    refreshAllPosts();

    res.json({
      success: true,
      message: 'Content updated successfully',
      post: targetData[postIndex]
    });
  } catch (error) {
    console.error('Update content error:', error);
    res.status(500).json({ error: 'Failed to update content' });
  }
});

app.get('/api/admin/content/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const postId = parseInt(id);

    const post = [...mangaData, ...novelsData].find(p => p.id === postId);
    
    if (!post) {
      return res.status(404).json({ error: 'Post not found' });
    }

    res.json({
      success: true,
      post
    });
  } catch (error) {
    console.error('Get content error:', error);
    res.status(500).json({ error: 'Failed to get content' });
  }
});

app.put('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;

    const userIndex = usersData.findIndex(user => user._id === id);
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (updates.password) {
      delete updates.password;
    }

    usersData[userIndex] = { ...usersData[userIndex], ...updates };
    await saveData('users', usersData);

    const { password, ...userWithoutPassword } = usersData[userIndex];
    
    res.json({
      success: true,
      user: userWithoutPassword,
      message: 'User updated successfully'
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});

app.get('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const user = usersData.find(user => user._id === id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const { password, ...userWithoutPassword } = user;
    
    res.json({
      success: true,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

app.put('/api/admin/chapter/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { manga, ...updates } = req.body;

    if (!manga) {
      return res.status(400).json({ error: 'Manga parameter is required' });
    }

    const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
    
    if (!chaptersData[normalizedTitle] || !chaptersData[normalizedTitle][id]) {
      return res.status(404).json({ error: 'Chapter not found' });
    }

    chaptersData[normalizedTitle][id] = { 
      ...chaptersData[normalizedTitle][id], 
      ...updates 
    };

    await saveChaptersData();

    res.json({
      success: true,
      message: 'Chapter updated successfully',
      chapter: chaptersData[normalizedTitle][id]
    });
  } catch (error) {
    console.error('Update chapter error:', error);
    res.status(500).json({ error: 'Failed to update chapter' });
  }
});

app.get('/api/admin/chapter/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { manga } = req.query;

    if (!manga) {
      return res.status(400).json({ error: 'Manga parameter is required' });
    }

    const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
    const chapter = chaptersData[normalizedTitle]?.[id];

    if (!chapter) {
      return res.status(404).json({ error: 'Chapter not found' });
    }

    res.json({
      success: true,
      chapter: {
        id,
        manga: normalizedTitle,
        ...chapter
      }
    });
  } catch (error) {
    console.error('Get chapter error:', error);
    res.status(500).json({ error: 'Failed to get chapter' });
  }
});

app.get('/api/admin/posts-dropdown', requireAdmin, async (req, res) => {
  try {
    const allPosts = [...mangaData, ...novelsData].map(post => ({
      id: post.id,
      title: post.title,
      type: post.type
    }));
    
    res.json({
      success: true,
      posts: allPosts
    });
  } catch (error) {
    console.error('Get posts dropdown error:', error);
    res.status(500).json({ error: 'Failed to get posts' });
  }
});

app.post('/api/admin/bulk-delete', requireAdmin, async (req, res) => {
  try {
    const { type, ids } = req.body;

    if (!type || !ids || !Array.isArray(ids)) {
      return res.status(400).json({ error: 'Invalid request parameters' });
    }

    let deletedCount = 0;

    switch (type) {
      case 'content':
        for (const id of ids) {
          const postId = parseInt(id);
          const mangaIndex = mangaData.findIndex(post => post.id === postId);
          if (mangaIndex !== -1) {
            const postTitle = mangaData[mangaIndex].title;
            const normalizedTitle = generateSlug(postTitle);
            
            if (chaptersData[normalizedTitle]) {
              delete chaptersData[normalizedTitle];
            }
            
            mangaData.splice(mangaIndex, 1);
            deletedCount++;
          } else {
            const novelIndex = novelsData.findIndex(post => post.id === postId);
            if (novelIndex !== -1) {
              const postTitle = novelsData[novelIndex].title;
              const normalizedTitle = generateSlug(postTitle);
              
              if (chaptersData[normalizedTitle]) {
                delete chaptersData[normalizedTitle];
              }
              
              novelsData.splice(novelIndex, 1);
              deletedCount++;
            }
          }
        }
        await saveData('manga', mangaData);
        await saveData('novels', novelsData);
        await saveChaptersData();
        refreshAllPosts();
        break;

      case 'users':
        for (const id of ids) {
          const userIndex = usersData.findIndex(user => user._id === id);
          if (userIndex !== -1) {
            usersData.splice(userIndex, 1);
            deletedCount++;
          }
        }
        await saveData('users', usersData);
        break;

      case 'chapters':
        for (const id of ids) {
          const { manga, chapterId } = id;
          const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
          
          if (chaptersData[normalizedTitle] && chaptersData[normalizedTitle][chapterId]) {
            delete chaptersData[normalizedTitle][chapterId];
            deletedCount++;
            
            if (Object.keys(chaptersData[normalizedTitle]).length === 0) {
              delete chaptersData[normalizedTitle];
            }
          }
        }
        await saveChaptersData();
        break;
    }

    res.json({
      success: true,
      message: `Successfully deleted ${deletedCount} items`,
      deletedCount
    });
  } catch (error) {
    console.error('Bulk delete error:', error);
    res.status(500).json({ error: 'Failed to delete items' });
  }
});

app.post('/api/start-timer/:manga/:chapterId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const userId = req.user._id;

    const chapter = findChapter(manga, chapterId);
    if (!chapter) {
      return res.status(404).json({ error: 'Chapter not found' });
    }

    const hasContent = (chapter.pages && chapter.pages.length > 0) || chapter.content;
    if (!hasContent) {
      return res.status(400).json({ error: 'No content available for this chapter' });
    }

    if (isChapterUnlocked(req.user, manga, chapterId)) {
      return res.json({
        success: true,
        alreadyUnlocked: true,
        message: 'Chapter is already unlocked'
      });
    }

    const timerKey = startChapterTimer(userId, chapterId, manga);  
    
    res.json({  
      success: true,  
      timerKey,  
      message: 'Timer started for chapter unlock'  
    });

  } catch (error) {
    console.error('Start timer error:', error);
    res.status(500).json({ error: 'Failed to start timer' });
  }
});

app.get('/api/check-timer/:manga/:chapterId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const userId = req.user._id;

    if (isChapterUnlocked(req.user, manga, chapterId)) {
      return res.json({
        success: true,
        alreadyUnlocked: true,
        message: 'Chapter is already unlocked'
      });
    }

    const timerStatus = checkChapterTimer(userId, chapterId, manga);  
    
    res.json({  
      success: true,  
      ...timerStatus  
    });

  } catch (error) {
    console.error('Check timer error:', error);
    res.status(500).json({ error: 'Failed to check timer' });
  }
});

app.post('/api/unlock-chapter/:manga/:chapterId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const userId = req.user._id;

    if (!validateAdCompletion(userId, manga, chapterId)) {
      return res.status(403).json({ error: 'Ad not completed. Please watch the full ad to unlock this chapter.' });
    }

    const success = await unlockChapterForUser(userId, manga, chapterId);  
    
    if (success) {  
      res.json({  
        success: true,  
        message: 'Chapter unlocked successfully'  
      });  
    } else {  
      res.status(400).json({ error: 'Failed to unlock chapter' });  
    }

  } catch (error) {
    console.error('Unlock chapter error:', error);
    res.status(500).json({ error: 'Failed to unlock chapter' });
  }
});

app.post('/api/lock-chapter/:manga/:chapterId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const userId = req.user._id;

    const success = lockChapterForUser(userId, manga, chapterId);  
    
    if (success) {  
      res.json({  
        success: true,  
        message: 'Chapter locked successfully'  
      });  
    } else {  
      res.status(400).json({ error: 'Chapter not found or already locked' });  
    }

  } catch (error) {
    console.error('Lock chapter error:', error);
    res.status(500).json({ error: 'Failed to lock chapter' });
  }
});

app.get('/api/user/:id/unlocked-chapters', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    res.json({  
      success: true,  
      unlockedChapters: user.unlockedChapters || []  
    });

  } catch (error) {
    console.error('Get unlocked chapters error:', error);
    res.status(500).json({ error: 'Failed to get unlocked chapters' });
  }
});

app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const user = findUserById(req.user._id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const { password, ...userWithoutPassword } = user;
    res.json({
      success: true,
      user: userWithoutPassword
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

app.get('/api/user/:id', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    const { password, ...userWithoutPassword } = user;  
    
    res.json({  
      success: true,  
      user: userWithoutPassword  
    });

  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user data' });
  }
});

app.put('/api/user/:id/name', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name } = req.body;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    if (!name) {  
      return res.status(400).json({ error: 'Name is required' });  
    }  

    const user = updateUser(id, { name });  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    const { password, ...userWithoutPassword } = user;  
    
    broadcastToUser(id, 'profileUpdate', { user: userWithoutPassword });  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      message: 'Name updated successfully'  
    });

  } catch (error) {
    console.error('Update name error:', error);
    res.status(500).json({ error: 'Failed to update name' });
  }
});

app.put('/api/user/:id/username', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { username } = req.body;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    if (!username) {  
      return res.status(400).json({ error: 'Username is required' });  
    }  

    const user = updateUser(id, { username });  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    const { password, ...userWithoutPassword } = user;  
    
    broadcastToUser(id, 'profileUpdate', { user: userWithoutPassword });  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      message: 'Username updated successfully'  
    });

  } catch (error) {
    console.error('Update username error:', error);
    res.status(500).json({ error: 'Failed to update username' });
  }
});

app.post('/api/user/:id/like/:postId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id, postId } = req.params;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    if (!user.likes) {  
      user.likes = [];  
    }  

    const postIdNum = parseInt(postId);  
    const likeIndex = user.likes.indexOf(postIdNum);  
    
    let message;
    if (likeIndex === -1) {  
      user.likes.push(postIdNum);  
      message = 'Post Liked';
      
      const post = allPosts.find(p => p.id === postIdNum);
      if (post) {
        post.totalLikes = (post.totalLikes || 0) + 1;
        if (post.type === 'manga') {
          await saveData('manga', mangaData);
        } else {
          await saveData('novels', novelsData);
        }
      }
    } else {  
      user.likes.splice(likeIndex, 1);  
      message = 'Post Unliked';
      
      const post = allPosts.find(p => p.id === postIdNum);
      if (post) {
        post.totalLikes = Math.max(0, (post.totalLikes || 1) - 1);
        if (post.type === 'manga') {
          await saveData('manga', mangaData);
        } else {
          await saveData('novels', novelsData);
        }
      }
    }  

    user.lastSeen = new Date().toISOString();  
    await saveData('users', usersData);  

    updateUserActivity(id, 'like', { postId: postIdNum, liked: likeIndex === -1 });

    broadcastToUser(id, 'likeUpdate', { likes: user.likes, postId: postIdNum, liked: likeIndex === -1 });  
    
    res.json({  
      success: true,  
      likes: user.likes,  
      liked: likeIndex === -1,
      message: message
    });

  } catch (error) {
    console.error('Like post error:', error);
    res.status(500).json({ error: 'Failed to like post' });
  }
});

app.post('/api/user/:id/readlater/:postId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id, postId } = req.params;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    if (!user.readLater) {  
      user.readLater = [];  
    }  

    const postIdNum = parseInt(postId);  
    const readLaterIndex = user.readLater.indexOf(postIdNum);  
    
    let message;
    if (readLaterIndex === -1) {  
      user.readLater.push(postIdNum);  
      message = 'Added to Read Later';
    } else {  
      user.readLater.splice(readLaterIndex, 1);  
      message = 'Removed from Read Later';
    }  

    user.lastSeen = new Date().toISOString();  
    await saveData('users', usersData);  

    updateUserActivity(id, 'readLater', { postId: postIdNum, added: readLaterIndex === -1 });

    broadcastToUser(id, 'readLaterUpdate', { readLater: user.readLater, postId: postIdNum, added: readLaterIndex === -1 });  
    
    res.json({  
      success: true,  
      readLater: user.readLater,  
      added: readLaterIndex === -1,
      message: message
    });

  } catch (error) {
    console.error('Read later error:', error);
    res.status(500).json({ error: 'Failed to update read later' });
  }
});

app.post('/api/user/:id/continue-reading', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { manga, chapterId } = req.body;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    user.continueReading = {  
      manga,  
      chapterId,  
      lastRead: new Date().toISOString()  
    };  

    user.lastSeen = new Date().toISOString();  
    await saveData('users', usersData);  

    updateUserActivity(id, 'continueReading', { manga, chapterId });
    
    res.json({  
      success: true,  
      continueReading: user.continueReading,  
      message: 'Continue reading updated'  
    });

  } catch (error) {
    console.error('Continue reading error:', error);
    res.status(500).json({ error: 'Failed to update continue reading' });
  }
});

app.get('/api/user/:id/continue-reading', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { id } = req.params;

    if (id !== req.user._id) {  
      return res.status(403).json({ error: 'Access denied' });  
    }  

    const user = findUserById(id);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    res.json({  
      success: true,  
      continueReading: user.continueReading || null  
    });

  } catch (error) {
    console.error('Get continue reading error:', error);
    res.status(500).json({ error: 'Failed to get continue reading' });
  }
});

app.post('/api/reading-track', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId, progress } = req.body;
    const userId = req.user._id;

    const user = findUserById(userId);  
    if (!user) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    if (!user.continueReading) {
      user.continueReading = {};
    }
    
    user.continueReading = {
      manga,
      chapterId,
      lastRead: new Date().toISOString(),
      progress: progress || 0
    };

    user.lastSeen = new Date().toISOString();  
    await saveData('users', usersData);  

    updateUserActivity(userId, 'readingProgress', { manga, chapterId, progress });
    
    res.json({  
      success: true,  
      message: 'Reading progress saved'  
    });

  } catch (error) {
    console.error('Reading track error:', error);
    res.status(500).json({ error: 'Failed to save reading progress' });
  }
});

app.post('/api/chapter/:manga/:chapterId/view', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const userId = req.user._id;

    if (!isChapterUnlocked(req.user, manga, chapterId)) {
      return res.status(403).json({ error: 'Chapter is locked. Please unlock it first.' });
    }

    const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
    if (chaptersData[normalizedTitle] && chaptersData[normalizedTitle][chapterId]) {
      chaptersData[normalizedTitle][chapterId].totalViews = 
        (chaptersData[normalizedTitle][chapterId].totalViews || 0) + 1;
      await saveChaptersData();
    }

    const user = findUserById(userId);
    if (user) {
      if (!user.readHistory) user.readHistory = [];
      
      user.readHistory = user.readHistory.filter(
        item => !(item.manga === manga && item.chapterId === chapterId)
      );
      
      user.readHistory.unshift({
        manga,
        chapterId,
        viewedAt: new Date().toISOString()
      });
      
      if (user.readHistory.length > 50) {
        user.readHistory = user.readHistory.slice(0, 50);
      }
      
      user.lastSeen = new Date().toISOString();
      await saveData('users', usersData);

      updateUserActivity(userId, 'chapterView', { manga, chapterId });
    }

    res.json({
      success: true,
      message: 'View tracked successfully'
    });

  } catch (error) {
    console.error('Track view error:', error);
    res.status(500).json({ error: 'Failed to track view' });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {  
      return res.status(400).json({ error: 'Name, email, and password are required' });  
    }  

    if (findUserByEmail(email)) {  
      return res.status(400).json({ error: 'User already exists' });  
    }  

    const hashedPassword = await bcrypt.hash(password, 12);  

    const newUser = {  
      _id: 'user-' + uuidv4(),  
      name,  
      email,  
      password: hashedPassword,  
      role: 'user',  
      createdAt: new Date().toISOString(),  
      lastSeen: new Date().toISOString(),  
      readHistory: [],  
      likedGenres: [],  
      unlockedChapters: [],  
      likes: [],  
      readLater: [],  
      viewedChapters: [],  
      searchHistory: []  
    };  

    usersData.push(newUser);  
    await saveData('users', usersData);  

    updateAnalytics();

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '7d' });  

    res.cookie('token', token, {  
      httpOnly: true,  
      secure: process.env.NODE_ENV === 'production',  
      maxAge: 7 * 24 * 60 * 60 * 1000
    });  

    const { password: _, ...userWithoutPassword } = newUser;  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      token,  
      message: 'Registration successful'  
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {  
      return res.status(400).json({ error: 'Email and password are required' });  
    }  

    const user = findUserByEmail(email);  
    if (!user) {  
      return res.status(401).json({ error: 'Invalid credentials' });  
    }  

    const isPasswordValid = await bcrypt.compare(password, user.password);  
    if (!isPasswordValid) {  
      return res.status(401).json({ error: 'Invalid credentials' });  
    }  

    user.lastSeen = new Date().toISOString();  
    await saveData('users', usersData);  

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });  

    res.cookie('token', token, {  
      httpOnly: true,  
      secure: process.env.NODE_ENV === 'production',  
      maxAge: 7 * 24 * 60 * 60 * 1000
    });  

    const { password: _, ...userWithoutPassword } = user;  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      token,  
      message: 'Login successful'  
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/guest-login', async (req, res) => {
  try {
    const { deviceId } = req.body;

    if (!deviceId) {  
      return res.status(400).json({ error: 'Device ID is required' });  
    }  

    let user = findUserByDeviceId(deviceId);  
    
    if (!user) {  
      const guestId = uuidv4();  
      user = {  
        _id: 'guest-' + guestId,  
        name: 'Guest User',  
        email: `guest-${guestId}@rovel.com`,  
        password: '',
        role: 'guest',  
        deviceId: deviceId,  
        createdAt: new Date().toISOString(),  
        lastSeen: new Date().toISOString(),  
        readHistory: [],  
        likedGenres: [],  
        unlockedChapters: [],  
        likes: [],  
        readLater: [],  
        viewedChapters: [],  
        searchHistory: []  
      };  

      usersData.push(user);  
      await saveData('users', usersData);  
    } else {  
      user.lastSeen = new Date().toISOString();  
      await saveData('users', usersData);  
    }  

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });  

    res.cookie('token', token, {  
      httpOnly: true,  
      secure: process.env.NODE_ENV === 'production',  
      maxAge: 7 * 24 * 60 * 60 * 1000
    });  

    const { password: _, ...userWithoutPassword } = user;  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      token,  
      message: 'Guest login successful'  
    });

  } catch (error) {
    console.error('Guest login error:', error);
    res.status(500).json({ error: 'Guest login failed' });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({
    success: true,
    message: 'Logout successful'
  });
});

app.post('/api/refresh-token', authenticateToken, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const token = jwt.sign({ userId: req.user._id }, JWT_SECRET, { expiresIn: '7d' });  

    res.cookie('token', token, {  
      httpOnly: true,  
      secure: process.env.NODE_ENV === 'production',  
      maxAge: 7 * 24 * 60 * 60 * 1000
    });  

    const { password: _, ...userWithoutPassword } = req.user;  
    
    res.json({  
      success: true,  
      user: userWithoutPassword,  
      token,  
      message: 'Token refreshed successfully'  
    });

  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(500).json({ error: 'Token refresh failed' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const stats = calculateStats();
    res.json({
      success: true,
      stats
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

app.get('/api/top-posts', async (req, res) => {
  try {
    const topPosts = getTopPosts();
    res.json({
      success: true,
      posts: topPosts
    });
  } catch (error) {
    console.error('Get top posts error:', error);
    res.status(500).json({ error: 'Failed to get top posts' });
  }
});

app.get('/api/top-searches', async (req, res) => {
  try {
    const topSearches = getTopSearches();
    res.json({
      success: true,
      searches: topSearches
    });
  } catch (error) {
    console.error('Get top searches error:', error);
    res.status(500).json({ error: 'Failed to get top searches' });
  }
});

app.get('/api/recent-users', async (req, res) => {
  try {
    const recentUsers = getRecentUsers();
    res.json({
      success: true,
      users: recentUsers
    });
  } catch (error) {
    console.error('Get recent users error:', error);
    res.status(500).json({ error: 'Failed to get recent users' });
  }
});

app.get('/api/admin/content', requireAdmin, async (req, res) => {
  try {
    const allContent = [...mangaData, ...novelsData];
    res.json({
      success: true,
      content: allContent
    });
  } catch (error) {
    console.error('Get admin content error:', error);
    res.status(500).json({ error: 'Failed to get content' });
  }
});

app.post('/api/admin/content', requireAdmin, async (req, res) => {
  try {
    const {
      title,
      type,
      cover,
      description,
      author,
      genres,
      status,
      rating
    } = req.body;

    if (!title || !type || !cover || !description || !author) {  
      return res.status(400).json({ error: 'Missing required fields' });  
    }  

    let targetData, targetFile;  
    
    if (type === 'manga') {  
      targetData = mangaData;  
      targetFile = 'manga';  
    } else if (type === 'novel') {  
      targetData = novelsData;  
      targetFile = 'novels';  
    } else {  
      return res.status(400).json({ error: 'Invalid type. Must be "manga" or "novel"' });  
    }  

    const newId = Math.max(0, ...targetData.map(p => p.id)) + 1;  
    const newPost = {  
      id: newId,  
      title,  
      type,  
      cover,  
      description,  
      author,  
      genres,  
      chapters_count: 0,  
      status: status || 'Ongoing',  
      rating: rating || 0,  
      created_at: new Date().toISOString(),  
      postedAt: new Date().toISOString(),  
      latest_chapter_id: "0",  
      totalViews: 0,
      totalLikes: 0,
      totalUnlocks: 0
    };  

    targetData.push(newPost);  
    await saveData(targetFile, targetData);  
    refreshAllPosts();

    res.json({  
      success: true,  
      message: 'Content created successfully',
      id: newId
    });

  } catch (error) {
    console.error('Admin create content error:', error);
    res.status(500).json({ error: 'Failed to create content' });
  }
});

app.delete('/api/admin/content/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const postId = parseInt(id);

    let targetData, targetFile, postTitle;  
    
    const mangaIndex = mangaData.findIndex(post => post.id === postId);  
    if (mangaIndex !== -1) {  
      targetData = mangaData;  
      targetFile = 'manga';  
      postTitle = mangaData[mangaIndex].title;  
      mangaData.splice(mangaIndex, 1);  
    } else {  
      const novelIndex = novelsData.findIndex(post => post.id === postId);  
      if (novelIndex !== -1) {  
        targetData = novelsData;  
        targetFile = 'novels';  
        postTitle = novelsData[novelIndex].title;  
        novelsData.splice(novelIndex, 1);  
      } else {  
        return res.status(404).json({ error: 'Post not found' });  
      }  
    }  

    if (postTitle) {  
      const normalizedTitle = generateSlug(postTitle);  
      if (chaptersData[normalizedTitle]) {  
        delete chaptersData[normalizedTitle];  
      }  
    }  

    await saveData(targetFile, targetData);  
    await saveChaptersData();  
    refreshAllPosts();

    res.json({  
      success: true,  
      message: 'Content deleted successfully'  
    });

  } catch (error) {
    console.error('Delete content error:', error);
    res.status(500).json({ error: 'Failed to delete content' });
  }
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    res.json({
      success: true,
      users: usersData
    });
  } catch (error) {
    console.error('Get admin users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.delete('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const userIndex = usersData.findIndex(user => user._id === id);  
    if (userIndex === -1) {  
      return res.status(404).json({ error: 'User not found' });  
    }  

    usersData.splice(userIndex, 1);  
    await saveData('users', usersData);  

    res.json({  
      success: true,  
      message: 'User deleted successfully'  
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/chapters', requireAdmin, async (req, res) => {
  try {
    const allChapters = [];
    
    Object.entries(chaptersData).forEach(([manga, chapters]) => {
      Object.entries(chapters).forEach(([chapterId, chapterData]) => {
        allChapters.push({
          id: chapterId,
          title: chapterData.title,
          parent: manga,
          type: chapterData.pages && chapterData.pages.length > 0 ? 'manga' : 'novel',
          number: parseInt(chapterId),
          views: chapterData.totalViews || 0,
          unlocks: chapterData.totalUnlocks || 0,
          status: 'published',
          published: chapterData.postedAt
        });
      });
    });
    
    res.json({
      success: true,
      chapters: allChapters
    });
  } catch (error) {
    console.error('Get admin chapters error:', error);
    res.status(500).json({ error: 'Failed to get chapters' });
  }
});

app.post('/api/admin/chapter', requireAdmin, async (req, res) => {
  try {
    const {
      parent,
      number,
      title,
      type,
      pages,
      content,
      backgroundImage,
      publishNow
    } = req.body;

    if (!parent || !number || !title) {  
      return res.status(400).json({ error: 'Missing required fields' });  
    }  

    const parentPost = [...mangaData, ...novelsData].find(post => post.id == parent);
    if (!parentPost) {
      return res.status(404).json({ error: 'Parent post not found' });
    }

    const normalizedTitle = generateSlug(parentPost.title);  
    
    if (!chaptersData[normalizedTitle]) {  
      chaptersData[normalizedTitle] = {};  
    }  

    chaptersData[normalizedTitle][number] = {  
      title,  
      pages: pages || [],  
      content: content || null,  
      totalViews: 0,  
      totalUnlocks: 0,
      postedAt: new Date().toISOString(),  
      unlockTimer: 40,  
      backgroundImage: backgroundImage || null  
    };  

    await updatePostChaptersCount(normalizedTitle);

    await saveChaptersData();  

    res.json({  
      success: true,  
      chapterId: number,  
      message: 'Chapter added successfully'  
    });

  } catch (error) {
    console.error('Add chapter error:', error);
    res.status(500).json({ error: 'Failed to add chapter' });
  }
});

app.delete('/api/admin/chapter/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { manga } = req.query;

    if (!manga) {  
      return res.status(400).json({ error: 'Manga parameter is required' });  
    }  

    const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');

    if (!chaptersData[normalizedTitle] || !chaptersData[normalizedTitle][id]) {  
      return res.status(404).json({ error: 'Chapter not found' });  
    }  

    delete chaptersData[normalizedTitle][id];  

    await updatePostChaptersCount(normalizedTitle);

    if (Object.keys(chaptersData[normalizedTitle]).length === 0) {  
      delete chaptersData[normalizedTitle];  
    }  

    await saveChaptersData();  

    res.json({  
      success: true,  
      message: 'Chapter deleted successfully'  
    });

  } catch (error) {
    console.error('Delete chapter error:', error);
    res.status(500).json({ error: 'Failed to delete chapter' });
  }
});

app.get('/api/rank', async (req, res) => {
  try {
    const { type = 'views' } = req.query;
    
    if (rankData.lastUpdated) {
      const lastUpdated = new Date(rankData.lastUpdated);
      const now = new Date();
      const hoursDiff = (now - lastUpdated) / (1000 * 60 * 60);

      if (hoursDiff < 1) {  
        let ranks = [];
        switch (type) {
          case 'views':
            ranks = rankData.byViews || [];
            break;
          case 'unlocks':
            ranks = rankData.byUnlocks || [];
            break;
          case 'likes':
            ranks = rankData.byLikes || [];
            break;
          default:
            ranks = rankData.byViews || [];
        }
        
        return res.json({  
          success: true,  
          ranks: ranks,  
          lastUpdated: rankData.lastUpdated  
        });  
      }  
    }  
    
    const freshRanks = await calculateRanks();  
    
    let ranks = [];
    switch (type) {
      case 'views':
        ranks = freshRanks.byViews || [];
        break;
      case 'unlocks':
        ranks = freshRanks.byUnlocks || [];
        break;
      case 'likes':
        ranks = freshRanks.byLikes || [];
        break;
      default:
        ranks = freshRanks.byViews || [];
    }
    
    res.json({  
      success: true,  
      ranks: ranks,  
      lastUpdated: freshRanks.lastUpdated  
    });

  } catch (error) {
    console.error('Get ranks error:', error);
    res.status(500).json({ error: 'Failed to get ranks' });
  }
});

app.get('/api/posts', (req, res) => {
  res.json({
    success: true,
    posts: allPosts
  });
});

app.get('/api/posts/:id', (req, res) => {
  const { id } = req.params;
  const post = allPosts.find(p => p.id === parseInt(id));

  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }

  res.json({
    success: true,
    post
  });
});

app.get('/api/manga', (req, res) => {
  res.json({
    success: true,
    manga: mangaData
  });
});

app.get('/api/novels', (req, res) => {
  res.json({
    success: true,
    novels: novelsData
  });
});

app.get('/api/chapters/:manga', (req, res) => {
  const { manga } = req.params;
  const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
  const chapters = chaptersData[normalizedTitle] || {};

  if (Object.keys(chapters).length === 0) {
    return res.json({
      success: true,
      chapters: {},
      message: 'No chapters available'
    });
  }

  res.json({
    success: true,
    chapters
  });
});

app.get('/api/chapter/:manga/:chapterId', authenticateToken, requireAuth, async (req, res) => {
  try {
    const { manga, chapterId } = req.params;
    const normalizedTitle = manga.toLowerCase().replace(/\s+/g, '-');
    const chapter = findChapter(manga, chapterId);

    if (!chapter) {  
      return res.status(404).json({ error: 'Chapter not found' });  
    }  

    if (!isChapterUnlocked(req.user, manga, chapterId)) {
      return res.status(403).json({ 
        error: 'Chapter is locked. Please watch an ad and wait for 40 seconds to unlock this chapter.',
        locked: true
      });
    }

    const hasContent = (chapter.pages && chapter.pages.length > 0) || chapter.content;
    if (!hasContent) {
      return res.status(400).json({ error: 'No content available for this chapter' });
    }

    applySecurityHeaders(res);

    chapter.totalViews = (chapter.totalViews || 0) + 1;  
    
    const viewKey = `${normalizedTitle}-${chapterId}`;  
    viewsData[viewKey] = (viewsData[viewKey] || 0) + 1;  
    
    await saveChaptersData();  
    await saveData('views', viewsData);  

    if (req.user) {  
      const user = findUserById(req.user._id);  
      if (user) {  
        if (!user.readHistory) user.readHistory = [];  
          
        user.readHistory = user.readHistory.filter(  
          item => !(item.manga === manga && item.chapterId === chapterId)  
        );  
          
        user.readHistory.unshift({  
          manga,  
          chapterId,  
          viewedAt: new Date().toISOString()  
        });  
          
        if (user.readHistory.length > 50) {  
          user.readHistory = user.readHistory.slice(0, 50);  
        }  
          
        user.lastSeen = new Date().toISOString();  
        await saveData('users', usersData);  

        updateUserActivity(req.user._id, 'chapterView', { manga, chapterId });
      }  
    }  

    res.json({  
      success: true,  
      chapter  
    });

  } catch (error) {
    console.error('Get chapter error:', error);
    res.status(500).json({ error: 'Failed to get chapter' });
  }
});

app.get('/api/ads-config', (req, res) => {
  res.json({
    success: true,
    config: adsConfigData
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    success: true,
    config: configData
  });
});

app.post('/api/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.body;

    if (!query) {  
      return res.json({  
        success: true,  
        results: []  
      });  
    }  

    const searchQuery = query.toLowerCase();  
    
    const results = allPosts.filter(post =>   
      post.title.toLowerCase().includes(searchQuery) ||  
      post.author.toLowerCase().includes(searchQuery) ||  
      post.genres.toLowerCase().includes(searchQuery) ||  
      post.description.toLowerCase().includes(searchQuery)  
    );  

    if (!searchData.searches) {
      searchData.searches = [];
    }
    
    searchData.searches.push({
      query,
      timestamp: new Date().toISOString(),
      userId: req.user ? req.user._id : 'anonymous'
    });
    
    if (searchData.searches.length > 1000) {
      searchData.searches = searchData.searches.slice(-1000);
    }
    
    await saveData('search', searchData);

    if (req.user) {  
      const user = findUserById(req.user._id);  
      if (user) {  
        if (!user.searchHistory) user.searchHistory = [];  
          
        const existingIndex = user.searchHistory.findIndex(  
          item => item.toLowerCase() === searchQuery  
        );  
          
        if (existingIndex === -1) {  
          user.searchHistory.unshift(query);  
          if (user.searchHistory.length > 20) {  
            user.searchHistory = user.searchHistory.slice(0, 20);  
          }  
            
          await saveData('users', usersData);  

          updateUserActivity(req.user._id, 'search', { query });
        }  
      }  
    }  

    res.json({  
      success: true,  
      results  
    });

  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

app.post('/api/upload-image', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const imageUrl = `/uploads/${req.file.filename}`;
    
    res.json({
      success: true,
      imageUrl,
      message: 'Image uploaded successfully'
    });
  } catch (error) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: 'Failed to upload image' });
  }
});

app.post('/api/upload-images', upload.array('images', 50), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No files uploaded' });
    }

    const imageUrls = req.files.map(file => `/uploads/${file.filename}`);
    
    res.json({
      success: true,
      imageUrls,
      message: 'Images uploaded successfully'
    });
  } catch (error) {
    console.error('Images upload error:', error);
    res.status(500).json({ error: 'Failed to upload images' });
  }
});

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

app.use('/uploads', express.static(path.join(__dirname, 'data', 'uploads', 'all_img')));

app.use('/protected-images', (req, res, next) => {
  next();
});

app.get(['/admin', '/admin/*'], (req, res) => {
  res.json({
    message: "Rovel Readers API Server",
    admin: "Admin panel frontend not deployed",
    api: "Use API endpoints at /api/*",
    health: "Check /api/health for server status"
  });

app.get('*', (req, res) => {
  res.json({
    message: "🚀 Rovel Readers API Server is running!",
    endpoints: {
      health: "/api/health",
      stats: "/api/stats", 
      posts: "/api/posts",
      manga: "/api/manga",
      novels: "/api/novels",
      admin: "/admin (API only)"
    },
    status: "Frontend not deployed - API only mode"
  });
});

app.use((error, req, res, next) => {
  console.error('Server error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

async function startServer() {
  await initializeData();

  startCleanupInterval();
  startRankCalculationInterval();

  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Loaded: ${mangaData.length} manga, ${novelsData.length} novels`);
    console.log(`👥 Users: ${usersData.length}, Chapters: ${Object.keys(chaptersData).length} series`);
    console.log(`🌐 Server ready`);
    console.log(`🔧 Admin panel: /admin`);
    console.log(`🔐 Admin credentials: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
  });
}

startServer().catch(console.error);
