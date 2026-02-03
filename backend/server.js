/**
 * CODATS - Code Analysis & Threat Scanning System
 * Main Server File
 */

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Load environment variables FIRST
require('dotenv').config();

// Check if .env file exists
if (!fs.existsSync('.env')) {
  console.warn('⚠️  Warning: .env file not found!');
  console.warn('   Create a .env file with:');
  console.warn('   GROQ_API_KEY=your_groq_api_key_here');
  console.warn('   AI_PROVIDER=groq');
  console.warn('   PORT=5000');
}

// Log environment status
console.log('Environment loaded:');
console.log('- PORT:', process.env.PORT || 5000);
console.log('- AI_PROVIDER:', process.env.AI_PROVIDER || 'groq');
console.log('- GROQ_API_KEY present:', !!process.env.GROQ_API_KEY);

const mongoose = require('mongoose');
const { scanCode, detectLanguage } = require('./scanner');
const { getAIAnalysis } = require('./ai/gemini'); // Change to ./ai/ai if you renamed

// Connect to MongoDB if MONGODB_URI provided
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI || '';
if (MONGODB_URI) {
  mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  }).then(() => console.log('✅ Connected to MongoDB'))
    .catch((err) => console.error('❌ MongoDB connection error:', err.message));
} else {
  console.warn('⚠️  MONGODB_URI not set. Authentication & persistence will be disabled.');
}

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedExtensions = ['.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.php', '.rb', '.go', '.c', '.cpp', '.cs'];
  const ext = path.extname(file.originalname).toLowerCase();
  
  if (allowedExtensions.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${ext} is not supported. Allowed types: ${allowedExtensions.join(', ')}`), false);
  }
};

const upload = multer({ 
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Routes

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'CODATS API is running',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    aiProvider: process.env.AI_PROVIDER || 'groq'
  });
});

/**
 * AI API health check
 * GET /api/ai/health
 */
app.get('/api/ai/health', async (req, res) => {
  try {
    const { testAPIConnectivity } = require('./ai/gemini'); // Change to ./ai/ai if renamed
    const result = await testAPIConnectivity();
    
    res.json({
      success: true,
      aiProvider: process.env.AI_PROVIDER || 'groq',
      apiStatus: result,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to check AI API status',
      details: error.message
    });
  }
});

/**
 * Main scan endpoint - accepts code directly
 * POST /api/scan
 * Body: { code: "...", language: "js" }
 */
app.post('/api/scan', async (req, res) => {
  try {
    const { code, language = 'javascript' } = req.body;

    if (!code || typeof code !== 'string') {
      return res.status(400).json({
        success: false,
        error: 'Code is required and must be a string'
      });
    }

    if (code.length > 500000) {
      return res.status(400).json({
        success: false,
        error: 'Code exceeds maximum length of 500,000 characters'
      });
    }

    console.log(`📝 Scanning ${code.length} characters of ${language} code...`);
    console.log(`🤖 AI Provider: ${process.env.AI_PROVIDER || 'groq'}`);

    // Scan for vulnerabilities
    const scanResults = scanCode(code, language);
    
    // Get AI analysis if vulnerabilities found
    let aiAnalysis = [];
    if (scanResults.vulnerabilities.length > 0) {
      console.log(`🔍 Found ${scanResults.vulnerabilities.length} vulnerabilities, getting AI analysis...`);
      try {
        aiAnalysis = await getAIAnalysis(scanResults.vulnerabilities, code, language);
        console.log(`✅ AI analysis complete: ${aiAnalysis.length} responses`);
      } catch (aiError) {
        console.error('❌ AI analysis failed:', aiError.message);
        // Continue without AI analysis
      }
    }

    // Combine results
    const response = {
      success: true,
      ...scanResults,
      aiAnalysis,
      aiProvider: process.env.AI_PROVIDER || 'groq',
      message: scanResults.vulnerabilities.length > 0 
        ? `Found ${scanResults.vulnerabilities.length} potential security issues`
        : 'No vulnerabilities detected'
    };

    res.json(response);
  } catch (error) {
    console.error('❌ Scan error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to scan code',
      details: error.message
    });
  }
});

/**
 * File upload scan endpoint
 * POST /api/scan/upload
 * Body: multipart/form-data with 'file' field
 */
app.post('/api/scan/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: 'No file uploaded'
      });
    }

    const filePath = req.file.path;
    const filename = req.file.originalname;
    
    console.log(`📁 Processing uploaded file: ${filename}`);

    // Read file content
    const code = fs.readFileSync(filePath, 'utf-8');
    
    // Detect language from file extension
    const language = detectLanguage(filename);
    
    console.log(`📝 Detected language: ${language}`);

    // Scan for vulnerabilities
    const scanResults = scanCode(code, language);
    
    // Get AI analysis if vulnerabilities found
    let aiAnalysis = [];
    if (scanResults.vulnerabilities.length > 0) {
      console.log(`🔍 Found ${scanResults.vulnerabilities.length} vulnerabilities, getting AI analysis...`);
      try {
        aiAnalysis = await getAIAnalysis(scanResults.vulnerabilities, code, language);
        console.log(`✅ AI analysis complete: ${aiAnalysis.length} responses`);
      } catch (aiError) {
        console.error('❌ AI analysis failed:', aiError.message);
        // Continue without AI analysis
      }
    }

    // Clean up uploaded file
    fs.unlinkSync(filePath);

    // Combine results
    const response = {
      success: true,
      filename,
      ...scanResults,
      aiAnalysis,
      aiProvider: process.env.AI_PROVIDER || 'groq',
      message: scanResults.vulnerabilities.length > 0 
        ? `Found ${scanResults.vulnerabilities.length} potential security issues in ${filename}`
        : 'No vulnerabilities detected'
    };

    res.json(response);
  } catch (error) {
    console.error('❌ File scan error:', error);
    
    // Clean up file if exists
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      error: 'Failed to scan uploaded file',
      details: error.message
    });
  }
});

/**
 * Get AI fix for a specific vulnerability
 * POST /api/fix
 * Body: { vulnerability: {...}, code: "..." }
 */
app.post('/api/fix', async (req, res) => {
  try {
    const { vulnerability, code } = req.body;

    if (!vulnerability) {
      return res.status(400).json({
        success: false,
        error: 'Vulnerability details are required'
      });
    }

    console.log(`🔧 Generating fix for ${vulnerability.type} on line ${vulnerability.line}`);

    // Get AI analysis for this specific vulnerability
    const aiAnalysis = await getAIAnalysis([vulnerability], code || '');

    if (aiAnalysis.length > 0) {
      res.json({
        success: true,
        aiProvider: process.env.AI_PROVIDER || 'groq',
        fix: aiAnalysis[0]
      });
    } else {
      res.json({
        success: true,
        aiProvider: process.env.AI_PROVIDER || 'groq',
        fix: {
          vulnerabilityId: vulnerability.id,
          explanation: vulnerability.description,
          fix: vulnerability.fix,
          confidence: 0.7
        }
      });
    }
  } catch (error) {
    console.error('❌ Fix generation error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate fix',
      details: error.message
    });
  }
});

/**
 * Get supported languages
 * GET /api/languages
 */
app.get('/api/languages', (req, res) => {
  res.json({
    success: true,
    languages: [
      { id: 'javascript', name: 'JavaScript', extensions: ['.js', '.jsx'] },
      { id: 'typescript', name: 'TypeScript', extensions: ['.ts', '.tsx'] },
      { id: 'python', name: 'Python', extensions: ['.py'] },
      { id: 'java', name: 'Java', extensions: ['.java'] },
      { id: 'php', name: 'PHP', extensions: ['.php'] },
      { id: 'go', name: 'Go', extensions: ['.go'] },
      { id: 'ruby', name: 'Ruby', extensions: ['.rb'] },
      { id: 'c', name: 'C', extensions: ['.c'] },
      { id: 'cpp', name: 'C++', extensions: ['.cpp', '.cc'] },
      { id: 'csharp', name: 'C#', extensions: ['.cs'] }
    ]
  });
});

/**
 * DB status
 * GET /api/db-status
 */
app.get('/api/db-status', (req, res) => {
  const readyState = mongoose.connection ? mongoose.connection.readyState : 0; // 0 disconnected, 1 connected
  res.json({ success: true, readyState, message: readyState === 1 ? 'connected' : 'disconnected' });
});

/**
 * Get vulnerability rules
 * GET /api/rules
 */
app.get('/api/rules', (req, res) => {
  const { vulnerabilityRules } = require('./rules');
  
  const rules = Object.entries(vulnerabilityRules).map(([key, rule]) => ({
    id: key,
    name: rule.name,
    severity: rule.severity,
    severityScore: rule.severityScore,
    description: rule.fix,
    patternCount: rule.patterns.length
  }));

  res.json({
    success: true,
    rules
  });
});

// Mount auth routes
const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('❌ Server error:', err);
  
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        error: 'File too large. Maximum size is 5MB.'
      });
    }
    return res.status(400).json({
      success: false,
      error: `Upload error: ${err.message}`
    });
  }
  
  res.status(500).json({
    success: false,
    error: err.message || 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found'
  });
});

// Start server
const HOST = process.env.HOST || '0.0.0.0';
app.listen(PORT, "0.0.0.0", () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     CODATS - Code Analysis & Threat Scanning System       ║
║                                                           ║
║     Server running on http://${HOST}:${PORT}              ║
║     AI Provider: ${process.env.AI_PROVIDER || 'groq'}     ║
║                                                           ║
║     Endpoints:                                            ║
║     • POST /api/scan        - Scan code                   ║
║     • POST /api/scan/upload - Upload and scan file        ║
║     • POST /api/fix         - Get AI fix recommendation   ║
║     • GET  /api/languages   - Get supported languages     ║
║     • GET  /api/rules       - Get vulnerability rules     ║
║     • GET  /api/health      - Health check                ║
║     • GET  /api/ai/health   - AI API health check         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;