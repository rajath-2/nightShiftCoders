const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files from public folder

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'Server is running', timestamp: new Date().toISOString() });
});

// Main prediction endpoint
app.post('/api/predict', async (req, res) => {
    console.log('📥 Prediction request received');
    console.log('Request body:', req.body);

    try {
        // Validate input
        if (!req.body.symptoms || !Array.isArray(req.body.symptoms)) {
            return res.status(400).json({ 
                error: 'Invalid input: symptoms must be an array',
                disease: 'Error',
                confidence: 0,
                precautions: [],
                needMoreInfo: true
            });
        }

        const symptoms = req.body.symptoms.filter(s => s && typeof s === 'string' && s.trim());
        
        if (symptoms.length === 0) {
            return res.status(400).json({ 
                error: 'No valid symptoms provided',
                disease: 'Unknown',
                confidence: 0,
                precautions: ['Please provide symptoms for diagnosis'],
                needMoreInfo: true
            });
        }

        console.log('🧹 Cleaned symptoms:', symptoms);

        // Path to Python script - adjust based on your file structure
        const pythonFile = path.join(__dirname, '../SymptomsToDisease/predict_api.py');
        
        console.log('🔍 Python script path:', pythonFile);
        console.log('🔍 Current directory:', __dirname);
        console.log('🔍 File exists:', fs.existsSync(pythonFile));
        
        // Check if Python file exists
        if (!fs.existsSync(pythonFile)) {
            console.error('❌ Python script not found:', pythonFile);
            return res.status(500).json({ 
                error: 'Prediction service not available - script not found',
                disease: 'Error',
                confidence: 0,
                precautions: [],
                needMoreInfo: true
            });
        }

        console.log('🐍 Spawning Python process...');
        console.log('Python file path:', pythonFile);
        console.log('Symptoms to send:', JSON.stringify(symptoms));
        console.log('Working directory:', process.cwd());

        // Spawn Python process
        const pythonProcess = spawn('python', [
            pythonFile,
            JSON.stringify(symptoms)
        ], {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: path.dirname(pythonFile) // Set working directory to Python script location
        });

        let result = '';
        let errorOutput = '';

        // Collect stdout
        pythonProcess.stdout.on('data', (data) => {
            result += data.toString();
        });

        // Collect stderr for debugging
        pythonProcess.stderr.on('data', (data) => {
            const errorMsg = data.toString();
            console.log('🐍 Python stderr:', errorMsg);
            errorOutput += errorMsg;
        });

        // Handle process completion
        pythonProcess.on('close', (code) => {
            console.log(`🐍 Python process exited with code: ${code}`);
            console.log('📤 Raw Python output:', result);

            if (code !== 0) {
                console.error('❌ Python process failed');
                console.error('Error output:', errorOutput);
                return res.status(500).json({ 
                    error: `Prediction failed (exit code: ${code})`,
                    disease: 'Error',
                    confidence: 0,
                    precautions: ['System error - please try again'],
                    needMoreInfo: true
                });
            }

            try {
                // Parse the JSON result
                const prediction = JSON.parse(result);
                console.log('✅ Parsed prediction:', prediction);

                // Ensure required fields exist
                const response = {
                    disease: prediction.disease || 'Unknown',
                    confidence: prediction.confidence || 0,
                    precautions: prediction.precautions || ['Consult a healthcare professional'],
                    needMoreInfo: prediction.needMoreInfo !== false,
                    ...(prediction.error && { error: prediction.error })
                };

                res.json(response);
            } catch (parseError) {
                console.error('❌ Failed to parse Python output:', parseError);
                console.error('Raw output was:', result);
                res.status(500).json({ 
                    error: 'Invalid prediction result format',
                    disease: 'Error',
                    confidence: 0,
                    precautions: ['System error - invalid response format'],
                    needMoreInfo: true
                });
            }
        });

        // Handle process errors
        pythonProcess.on('error', (error) => {
            console.error('❌ Failed to start Python process:', error);
            res.status(500).json({ 
                error: 'Failed to start prediction service',
                disease: 'Error',
                confidence: 0,
                precautions: ['System error - service unavailable'],
                needMoreInfo: true
            });
        });

        // Set timeout for the request
        const timeout = setTimeout(() => {
            pythonProcess.kill();
            res.status(408).json({ 
                error: 'Prediction request timed out',
                disease: 'Error',
                confidence: 0,
                precautions: ['System timeout - please try again'],
                needMoreInfo: true
            });
        }, 30000); // 30 second timeout

        pythonProcess.on('close', () => {
            clearTimeout(timeout);
        });

    } catch (error) {
        console.error('❌ Server error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            disease: 'Error',
            confidence: 0,
            precautions: ['System error - please try again later'],
            needMoreInfo: true
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('❌ Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        disease: 'Error',
        confidence: 0,
        precautions: [],
        needMoreInfo: true
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('🚀 Server started successfully');
    console.log(`🌐 Server running on http://localhost:${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
    console.log(`🩺 Prediction API: http://localhost:${PORT}/api/predict`);
    
    // Test Python availability
    const { spawn } = require('child_process');
    const testPython = spawn('python', ['--version']);
    testPython.on('close', (code) => {
        if (code === 0) {
            console.log('✅ Python is available');
        } else {
            console.log('⚠️  Warning: Python may not be available');
        }
    });
    testPython.on('error', () => {
        console.log('⚠️  Warning: Python is not in PATH');
    });
});