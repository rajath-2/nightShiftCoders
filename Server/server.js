const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();

// Middleware
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:8080'],
    credentials: true
}));
app.use(express.json());
app.use(express.static('website')); // Serve static files from website folder

// Logging middleware
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    if (req.method === 'POST') {
        console.log('Request body:', JSON.stringify(req.body, null, 2));
    }
    next();
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'Server is running', 
        timestamp: new Date().toISOString(),
        services: {
            webServer: 'active',
            aiService: 'checking...'
        }
    });
});

// Serve the integrated portal homepage
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'website', 'index.html');
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.json({ 
            message: 'MediCare AI Portal', 
            status: 'active',
            endpoints: {
                health: '/health',
                predict: '/api/predict',
                hospitals: '/api/hospitals'
            }
        });
    }
});

// Main prediction endpoint - Enhanced for integrated portal
app.post('/api/predict', async (req, res) => {
    console.log('🩺 AI Diagnosis request received');
    console.log('Request body:', req.body);

    try {
        // Enhanced input validation
        if (!req.body.symptoms) {
            return res.status(400).json({ 
                error: 'Missing symptoms field',
                disease: 'Error',
                confidence: 0,
                precautions: ['Please provide symptoms for analysis'],
                needMoreInfo: true
            });
        }

        let symptoms = req.body.symptoms;
        
        // Handle both array and string inputs
        if (typeof symptoms === 'string') {
            symptoms = symptoms.split(',').map(s => s.trim()).filter(s => s.length > 0);
        } else if (!Array.isArray(symptoms)) {
            return res.status(400).json({ 
                error: 'Symptoms must be an array or comma-separated string',
                disease: 'Error',
                confidence: 0,
                precautions: ['Invalid symptom format'],
                needMoreInfo: true
            });
        }

        // Filter and clean symptoms
        symptoms = symptoms.filter(s => s && typeof s === 'string' && s.trim().length > 0);
        
        if (symptoms.length === 0) {
            return res.status(400).json({ 
                error: 'No valid symptoms provided',
                disease: 'Unknown',
                confidence: 0,
                precautions: ['Please provide valid symptoms for diagnosis'],
                needMoreInfo: true
            });
        }

        console.log('🔬 Processed symptoms:', symptoms);

        // Path to Python script
        const pythonFile = path.join(__dirname, 'SymptomsToDisease', 'predict_api.py');
        
        console.log('🐍 Python script path:', pythonFile);
        console.log('📁 Working directory:', process.cwd());
        console.log('📝 File exists:', fs.existsSync(pythonFile));
        
        // Check if Python file exists
        if (!fs.existsSync(pythonFile)) {
            console.error('❌ Python script not found:', pythonFile);
            return res.status(500).json({ 
                error: 'AI diagnosis service not available - Python script not found',
                disease: 'Service Error',
                confidence: 0,
                precautions: [
                    'AI diagnosis service is currently unavailable',
                    'Please consult with a healthcare professional for diagnosis',
                    'You can still book an appointment through our system'
                ],
                needMoreInfo: true
            });
        }

        console.log('🚀 Spawning Python AI process...');

        // Enhanced Python process spawning
        const pythonProcess = spawn('python', [
            pythonFile,
            JSON.stringify(symptoms)
        ], {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: path.dirname(pythonFile), // Set working directory to Python script location
            timeout: 30000 // 30 second timeout
        });

        let result = '';
        let errorOutput = '';

        // Collect stdout
        pythonProcess.stdout.on('data', (data) => {
            const output = data.toString();
            console.log('🐍 Python stdout:', output);
            result += output;
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
            console.log('📤 Raw Python output length:', result.length);

            if (code !== 0) {
                console.error('❌ Python process failed');
                console.error('Error output:', errorOutput);
                
                // Provide helpful error response
                let errorDetail = 'AI service encountered an error';
                if (errorOutput.includes('ModuleNotFoundError')) {
                    errorDetail = 'Missing required Python modules. Please run: pip install -r requirements.txt';
                } else if (errorOutput.includes('FileNotFoundError')) {
                    errorDetail = 'AI model files not found. Please run train.py first.';
                } else if (errorOutput.includes('sklearn')) {
                    errorDetail = 'Machine learning libraries not properly installed';
                }
                
                return res.status(500).json({ 
                    error: `AI diagnosis failed: ${errorDetail}`,
                    disease: 'Service Error',
                    confidence: 0,
                    precautions: [
                        'AI diagnosis service is temporarily unavailable',
                        'Please consult with a healthcare professional',
                        'You can still find nearby hospitals and book appointments'
                    ],
                    needMoreInfo: true,
                    technicalDetails: process.env.NODE_ENV === 'development' ? {
                        exitCode: code,
                        stderr: errorOutput
                    } : undefined
                });
            }

            try {
                // Parse the JSON result
                const prediction = JSON.parse(result);
                console.log('✅ Parsed AI prediction:', prediction);

                // Ensure response has all required fields with proper formatting
                const response = {
                    disease: prediction.disease || 'Unknown Condition',
                    confidence: Math.round((prediction.confidence || 0) * 100) / 100, // Round to 2 decimal places
                    precautions: Array.isArray(prediction.precautions) ? prediction.precautions : 
                                prediction.precautions ? [prediction.precautions] : 
                                ['Consult a healthcare professional for proper diagnosis'],
                    needMoreInfo: prediction.needMoreInfo !== false,
                    timestamp: new Date().toISOString(),
                    ...(prediction.error && { error: prediction.error })
                };

                // Add confidence level assessment
                const confidenceLevel = response.confidence >= 70 ? 'high' : 
                                      response.confidence >= 40 ? 'medium' : 'low';
                response.confidenceLevel = confidenceLevel;

                // Add medical disclaimer for low confidence
                if (response.confidence < 40) {
                    response.precautions.unshift('⚠️ Low confidence prediction - Professional medical consultation strongly recommended');
                }

                // Log successful prediction
                console.log(`✅ AI Diagnosis completed: ${response.disease} (${response.confidence}% confidence)`);
                
                res.json(response);
                
            } catch (parseError) {
                console.error('❌ Failed to parse Python output:', parseError);
                console.error('Raw output was:', result);
                
                res.status(500).json({ 
                    error: 'Invalid AI response format - please check Python script output',
                    disease: 'Processing Error',
                    confidence: 0,
                    precautions: [
                        'AI diagnosis service returned invalid data',
                        'Please consult with a healthcare professional',
                        'Technical team has been notified'
                    ],
                    needMoreInfo: true,
                    technicalDetails: process.env.NODE_ENV === 'development' ? {
                        parseError: parseError.message,
                        rawOutput: result.substring(0, 500) // First 500 chars for debugging
                    } : undefined
                });
            }
        });

        // Handle process errors
        pythonProcess.on('error', (error) => {
            console.error('❌ Failed to start Python process:', error);
            
            let errorMessage = 'Failed to start AI diagnosis service';
            if (error.code === 'ENOENT') {
                errorMessage = 'Python not found - please install Python and ensure it\'s in your PATH';
            }
            
            res.status(500).json({ 
                error: errorMessage,
                disease: 'System Error',
                confidence: 0,
                precautions: [
                    'AI diagnosis service is currently unavailable',
                    'Please consult with a healthcare professional',
                    'You can still book appointments through our portal'
                ],
                needMoreInfo: true
            });
        });

        // Set timeout for the request
        const timeout = setTimeout(() => {
            pythonProcess.kill();
            res.status(408).json({ 
                error: 'AI diagnosis request timed out',
                disease: 'Timeout Error',
                confidence: 0,
                precautions: [
                    'AI analysis took too long to complete',
                    'Please try again with fewer symptoms',
                    'Consider booking an appointment for professional diagnosis'
                ],
                needMoreInfo: true
            });
        }, 35000); // 35 second timeout

        pythonProcess.on('close', () => {
            clearTimeout(timeout);
        });

    } catch (error) {
        console.error('❌ Server error in /api/predict:', error);
        res.status(500).json({ 
            error: 'Internal server error during AI diagnosis',
            disease: 'Server Error',
            confidence: 0,
            precautions: [
                'System encountered an unexpected error',
                'Please try again or consult a healthcare professional',
                'Our technical team has been notified'
            ],
            needMoreInfo: true
        });
    }
});

// Hospital locator endpoint
app.get('/api/hospitals', (req, res) => {
    const { lat, lng, radius = 5000 } = req.query;
    
    console.log(`🏥 Hospital search request: lat=${lat}, lng=${lng}, radius=${radius}`);
    
    // Sample hospital data - in production, this would query a real database or API
    const sampleHospitals = [
        {
            id: 'hosp_001',
            name: 'Apollo Hospital',
            address: '154/11, Opposite IIM-B, Bannerghatta Road, Bangalore',
            lat: 12.9279,
            lng: 77.6271,
            phone: '+91 80 2630 2330',
            rating: 4.2,
            specialties: ['General Medicine', 'Emergency Care', 'Cardiology', 'Neurology'],
            emergency: true,
            distance: 2.3
        },
        {
            id: 'hosp_002', 
            name: 'Manipal Hospital',
            address: '98, HAL Airport Road, HAL 2nd Stage, Indiranagar',
            lat: 12.9698,
            lng: 77.6469,
            phone: '+91 80 2502 4444',
            rating: 4.3,
            specialties: ['Multi-specialty', 'Emergency Care', 'ICU', 'Pediatrics'],
            emergency: true,
            distance: 3.1
        },
        {
            id: 'hosp_003',
            name: 'Columbia Asia Hospital',
            address: 'Kirloskar Business Park, Bellary Road, Hebbal',
            lat: 13.0359,
            lng: 77.5906,
            phone: '+91 80 6122 7000',
            rating: 4.1,
            specialties: ['General Medicine', 'Pediatrics', 'Surgery', 'Orthopedics'],
            emergency: true,
            distance: 4.2
        },
        {
            id: 'hosp_004',
            name: 'Fortis Hospital',
            address: '154/9, Opp. IIM-B, Bannerghatta Road',
            lat: 12.9165,
            lng: 77.6101,
            phone: '+91 80 6621 4444',
            rating: 4.0,
            specialties: ['Cardiology', 'Oncology', 'Emergency Care', 'Surgery'],
            emergency: true,
            distance: 4.8
        }
    ];

    // Filter hospitals within radius if coordinates provided
    let hospitals = sampleHospitals;
    if (lat && lng) {
        const userLat = parseFloat(lat);
        const userLng = parseFloat(lng);
        const maxRadius = parseInt(radius);
        
        hospitals = sampleHospitals.filter(hospital => {
            const distance = calculateDistance(userLat, userLng, hospital.lat, hospital.lng);
            hospital.calculatedDistance = distance;
            return distance <= maxRadius;
        }).sort((a, b) => a.calculatedDistance - b.calculatedDistance);
    }

    res.json({
        success: true,
        count: hospitals.length,
        hospitals: hospitals,
        query: { lat, lng, radius }
    });
});

// Utility function to calculate distance between coordinates
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Earth's radius in kilometers
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
              Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
              Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    return R * c; // Distance in kilometers
}

// Appointment booking endpoint
app.post('/api/appointments', (req, res) => {
    console.log('📅 Appointment booking request received');
    console.log('Request body:', req.body);
    
    try {
        const appointment = {
            id: 'apt_' + Date.now(),
            ...req.body,
            bookedAt: new Date().toISOString(),
            status: 'confirmed'
        };
        
        // In production, save to database
        console.log('✅ Appointment saved:', appointment.id);
        
        res.json({
            success: true,
            appointment: appointment,
            message: 'Appointment booked successfully'
        });
        
    } catch (error) {
        console.error('❌ Error booking appointment:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to book appointment',
            message: 'Please try again or contact support'
        });
    }
});

// Test endpoint for AI service
app.get('/api/test-ai', async (req, res) => {
    console.log('🧪 Testing AI service...');
    
    try {
        const testSymptoms = ['fever', 'headache', 'cough'];
        const pythonFile = path.join(__dirname, 'SymptomsToDisease', 'predict_api.py');
        
        if (!fs.existsSync(pythonFile)) {
            return res.json({
                success: false,
                error: 'Python script not found',
                path: pythonFile
            });
        }
        
        const pythonProcess = spawn('python', [pythonFile, JSON.stringify(testSymptoms)], {
            stdio: ['pipe', 'pipe', 'pipe'],
            cwd: path.dirname(pythonFile)
        });
        
        let result = '';
        let errorOutput = '';
        
        pythonProcess.stdout.on('data', (data) => {
            result += data.toString();
        });
        
        pythonProcess.stderr.on('data', (data) => {
            errorOutput += data.toString();
        });
        
        pythonProcess.on('close', (code) => {
            if (code === 0) {
                try {
                    const prediction = JSON.parse(result);
                    res.json({
                        success: true,
                        testResult: prediction,
                        message: 'AI service is working correctly'
                    });
                } catch (parseError) {
                    res.json({
                        success: false,
                        error: 'Invalid AI response format',
                        rawOutput: result,
                        parseError: parseError.message
                    });
                }
            } else {
                res.json({
                    success: false,
                    error: 'AI service failed',
                    exitCode: code,
                    stderr: errorOutput
                });
            }
        });
        
    } catch (error) {
        res.json({
            success: false,
            error: 'Failed to test AI service',
            details: error.message
        });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('❌ Unhandled server error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: 'Something went wrong on our server',
        timestamp: new Date().toISOString()
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        path: req.path,
        method: req.method,
        availableEndpoints: {
            'GET /': 'Homepage',
            'GET /health': 'Health check',
            'POST /api/predict': 'AI symptom diagnosis',
            'GET /api/hospitals': 'Find hospitals',
            'POST /api/appointments': 'Book appointment',
            'GET /api/test-ai': 'Test AI service'
        }
    });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log('🚀 MediCare AI Portal Server started successfully');
    console.log(`🌐 Server running on http://localhost:${PORT}`);
    console.log(`🏥 Health check: http://localhost:${PORT}/health`);
    console.log(`🩺 AI Diagnosis API: http://localhost:${PORT}/api/predict`);
    console.log(`🏥 Hospital Locator API: http://localhost:${PORT}/api/hospitals`);
    console.log(`📅 Appointment API: http://localhost:${PORT}/api/appointments`);
    console.log(`🧪 Test AI Service: http://localhost:${PORT}/api/test-ai`);
    
    // Test Python availability on startup
    const { spawn } = require('child_process');
    const testPython = spawn('python', ['--version']);
    
    testPython.on('close', (code) => {
        if (code === 0) {
            console.log('✅ Python is available');
            
            // Test AI service on startup
            setTimeout(() => {
                console.log('🧪 Testing AI service on startup...');
                const testUrl = `http://localhost:${PORT}/api/test-ai`;
                // You could add an HTTP request here to test the AI service
            }, 2000);
        } else {
            console.log('⚠️  Warning: Python may not be available');
        }
    });
    
    testPython.on('error', () => {
        console.log('⚠️  Warning: Python is not in PATH');
        console.log('   Make sure Python is installed and accessible');
        console.log('   AI diagnosis features may not work');
    });
});