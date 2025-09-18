// auth.js - Authentication Middleware and Routes
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const DatabaseManager = require('./database');

class AuthenticationManager {
    constructor() {
        this.db = new DatabaseManager();
        this.JWT_SECRET = process.env.JWT_SECRET || this.generateSecureSecret();
        this.JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
        this.REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '30d';
    }

    generateSecureSecret() {
        // Generate a secure random secret if not provided
        return crypto.randomBytes(64).toString('hex');
    }

    // JWT Token Methods
    signToken(id) {
        return jwt.sign({ id }, this.JWT_SECRET, {
            expiresIn: this.JWT_EXPIRES_IN,
            issuer: 'MediCare',
            audience: 'MediCare-Users'
        });
    }

    createSendToken(user, statusCode, res) {
        const token = this.signToken(user._id);
        
        const cookieOptions = {
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        };

        res.cookie('jwt', token, cookieOptions);

        // Remove password from output
        user.password = undefined;

        res.status(statusCode).json({
            status: 'success',
            token,
            data: {
                user
            }
        });
    }

    // Middleware for protecting routes
    async protect(req, res, next) {
        try {
            // 1) Getting token and check if it exists
            let token;
            if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
                token = req.headers.authorization.split(' ')[1];
            } else if (req.cookies.jwt) {
                token = req.cookies.jwt;
            }

            if (!token) {
                return res.status(401).json({
                    status: 'fail',
                    message: 'You are not logged in! Please log in to get access.'
                });
            }

            // 2) Verification token
            const decoded = jwt.verify(token, this.JWT_SECRET);

            // 3) Check if user still exists
            const currentUser = await this.db.models.User.findById(decoded.id);
            if (!currentUser) {
                return res.status(401).json({
                    status: 'fail',
                    message: 'The user belonging to this token does no longer exist.'
                });
            }

            // 4) Check if user is active
            if (!currentUser.isActive) {
                return res.status(401).json({
                    status: 'fail',
                    message: 'Your account has been deactivated. Please contact support.'
                });
            }

            // Grant access to protected route
            req.user = currentUser;
            next();
        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                return res.status(401).json({
                    status: 'fail',
                    message: 'Invalid token. Please log in again!'
                });
            } else if (error.name === 'TokenExpiredError') {
                return res.status(401).json({
                    status: 'fail',
                    message: 'Your token has expired! Please log in again.'
                });
            }
            
            return res.status(500).json({
                status: 'error',
                message: 'Something went wrong during authentication'
            });
        }
    }

    // Middleware for restricting to certain roles
    restrictTo(...roles) {
        return (req, res, next) => {
            if (!roles.includes(req.user.role)) {
                return res.status(403).json({
                    status: 'fail',
                    message: 'You do not have permission to perform this action'
                });
            }
            next();
        };
    }

    // Rate limiting configurations
    createAuthLimiters() {
        return {
            login: rateLimit({
                windowMs: 15 * 60 * 1000, // 15 minutes
                max: 5,
                message: 'Too many login attempts, please try again later.',
                standardHeaders: true,
                legacyHeaders: false,
                skipSuccessfulRequests: true
            }),
            
            register: rateLimit({
                windowMs: 60 * 60 * 1000, // 1 hour
                max: 3,
                message: 'Too many registration attempts, please try again later.',
                standardHeaders: true,
                legacyHeaders: false
            }),
            
            forgotPassword: rateLimit({
                windowMs: 60 * 60 * 1000, // 1 hour
                max: 3,
                message: 'Too many password reset requests, please try again later.',
                standardHeaders: true,
                legacyHeaders: false
            })
        };
    }

    // Security middleware
    securityMiddleware() {
        return [
            helmet({
                contentSecurityPolicy: {
                    directives: {
                        defaultSrc: ["'self'"],
                        styleSrc: ["'self'", "'unsafe-inline'"],
                        scriptSrc: ["'self'"],
                        imgSrc: ["'self'", "data:", "https:"],
                        connectSrc: ["'self'"],
                        fontSrc: ["'self'"],
                        objectSrc: ["'none'"],
                        mediaSrc: ["'self'"],
                        frameSrc: ["'none'"]
                    }
                }
            })
        ];
    }

    // Input sanitization
    sanitizeInput(input) {
        if (typeof input === 'string') {
            return validator.escape(input.trim());
        }
        return input;
    }

    // Validation helpers
    validateRegistrationInput(data) {
        const errors = [];
        
        if (!data.email || !validator.isEmail(data.email)) {
            errors.push('Valid email is required');
        }
        
        if (!data.password || !validator.isLength(data.password, { min: 8 })) {
            errors.push('Password must be at least 8 characters long');
        }
        
        if (!validator.isStrongPassword(data.password, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })) {
            errors.push('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
        }
        
        return errors;
    }

    // Authentication Routes
    getAuthRoutes(express) {
        const router = express.Router();
        const limiters = this.createAuthLimiters();

        // Apply security middleware
        router.use(this.securityMiddleware());

        // Register
        router.post('/register', limiters.register, async (req, res) => {
            try {
                const { email, password, fullName } = req.body;
                
                // Validate input
                const validationErrors = this.validateRegistrationInput({ email, password });
                if (validationErrors.length > 0) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Validation failed',
                        errors: validationErrors
                    });
                }

                // Sanitize input
                const sanitizedData = {
                    email: validator.normalizeEmail(email),
                    password: password, // Don't sanitize password
                    fullName: this.sanitizeInput(fullName)
                };

                // Create user
                const result = await this.db.createUser(sanitizedData);
                
                res.status(201).json({
                    status: 'success',
                    message: 'User registered successfully. Please check your email for verification.',
                    data: {
                        user: result.user
                    }
                });
                
            } catch (error) {
                console.error('Registration error:', error);
                
                if (error.message.includes('already exists')) {
                    return res.status(409).json({
                        status: 'fail',
                        message: 'User already exists with this email'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Registration failed. Please try again.'
                });
            }
        });

        // Login
        router.post('/login', limiters.login, async (req, res) => {
            try {
                const { email, password } = req.body;
                
                // Check if email and password exist
                if (!email || !password) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide email and password'
                    });
                }

                // Validate email format
                if (!validator.isEmail(email)) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide a valid email address'
                    });
                }

                // Authenticate user
                const user = await this.db.authenticateUser(email, password);
                
                // Generate and send token
                this.createSendToken(user, 200, res);
                
            } catch (error) {
                console.error('Login error:', error);
                
                if (error.message.includes('Invalid credentials')) {
                    return res.status(401).json({
                        status: 'fail',
                        message: 'Incorrect email or password'
                    });
                }
                
                if (error.message.includes('locked')) {
                    return res.status(423).json({
                        status: 'fail',
                        message: 'Account temporarily locked due to too many failed attempts'
                    });
                }
                
                if (error.message.includes('deactivated')) {
                    return res.status(403).json({
                        status: 'fail',
                        message: 'Account has been deactivated. Please contact support.'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Login failed. Please try again.'
                });
            }
        });

        // Logout
        router.post('/logout', async (req, res) => {
            res.cookie('jwt', 'loggedout', {
                expires: new Date(Date.now() + 10 * 1000),
                httpOnly: true
            });
            
            res.status(200).json({
                status: 'success',
                message: 'Logged out successfully'
            });
        });

        // Forgot Password
        router.post('/forgot-password', limiters.forgotPassword, async (req, res) => {
            try {
                const { email } = req.body;
                
                if (!email || !validator.isEmail(email)) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide a valid email address'
                    });
                }
                
                const user = await this.db.models.User.findOne({ email: validator.normalizeEmail(email) });
                
                if (!user) {
                    // Don't reveal whether user exists or not
                    return res.status(200).json({
                        status: 'success',
                        message: 'If an account with that email exists, a password reset link has been sent.'
                    });
                }
                
                const resetToken = user.createPasswordResetToken();
                await user.save({ validateBeforeSave: false });
                
                // In production, send email with resetToken
                console.log('Password reset token:', resetToken);
                
                res.status(200).json({
                    status: 'success',
                    message: 'If an account with that email exists, a password reset link has been sent.',
                    // Remove this in production
                    resetToken: process.env.NODE_ENV === 'development' ? resetToken : undefined
                });
                
            } catch (error) {
                console.error('Forgot password error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to process password reset request'
                });
            }
        });

        // Reset Password
        router.patch('/reset-password/:token', async (req, res) => {
            try {
                const { password, passwordConfirm } = req.body;
                const { token } = req.params;
                
                if (!password || !passwordConfirm) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide password and password confirmation'
                    });
                }
                
                if (password !== passwordConfirm) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Passwords do not match'
                    });
                }
                
                if (!validator.isStrongPassword(password)) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Password must be at least 8 characters with uppercase, lowercase, number and special character'
                    });
                }
                
                await this.db.resetPassword(token, password);
                
                res.status(200).json({
                    status: 'success',
                    message: 'Password has been reset successfully'
                });
                
            } catch (error) {
                console.error('Reset password error:', error);
                
                if (error.message.includes('invalid') || error.message.includes('expired')) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Token is invalid or has expired'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to reset password'
                });
            }
        });

        // Verify Email
        router.get('/verify-email/:token', async (req, res) => {
            try {
                const { token } = req.params;
                
                await this.db.verifyEmail(token);
                
                res.status(200).json({
                    status: 'success',
                    message: 'Email verified successfully'
                });
                
            } catch (error) {
                console.error('Email verification error:', error);
                
                if (error.message.includes('invalid') || error.message.includes('expired')) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Verification link is invalid or has expired'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Email verification failed'
                });
            }
        });

        // Change Password (for logged in users)
        router.patch('/change-password', this.protect.bind(this), async (req, res) => {
            try {
                const { currentPassword, newPassword, passwordConfirm } = req.body;
                
                if (!currentPassword || !newPassword || !passwordConfirm) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide current password, new password, and confirmation'
                    });
                }
                
                if (newPassword !== passwordConfirm) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'New passwords do not match'
                    });
                }
                
                if (!validator.isStrongPassword(newPassword)) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'New password must be at least 8 characters with uppercase, lowercase, number and special character'
                    });
                }
                
                await this.db.changePassword(req.user._id, currentPassword, newPassword);
                
                res.status(200).json({
                    status: 'success',
                    message: 'Password changed successfully'
                });
                
            } catch (error) {
                console.error('Change password error:', error);
                
                if (error.message.includes('incorrect')) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Current password is incorrect'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to change password'
                });
            }
        });

        // Get current user
        router.get('/me', this.protect.bind(this), async (req, res) => {
            try {
                const userWithPatient = await this.db.getUserWithPatient(req.user._id);
                
                res.status(200).json({
                    status: 'success',
                    data: userWithPatient
                });
                
            } catch (error) {
                console.error('Get user error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to fetch user data'
                });
            }
        });

        // Update user profile
        router.patch('/update-me', this.protect.bind(this), async (req, res) => {
            try {
                // Filter out sensitive fields
                const allowedFields = ['email'];
                const filteredBody = {};
                
                Object.keys(req.body).forEach(key => {
                    if (allowedFields.includes(key)) {
                        filteredBody[key] = this.sanitizeInput(req.body[key]);
                    }
                });
                
                // Validate email if provided
                if (filteredBody.email && !validator.isEmail(filteredBody.email)) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please provide a valid email address'
                    });
                }
                
                const updatedUser = await this.db.models.User.findByIdAndUpdate(
                    req.user._id,
                    filteredBody,
                    { new: true, runValidators: true }
                );
                
                res.status(200).json({
                    status: 'success',
                    data: {
                        user: updatedUser
                    }
                });
                
            } catch (error) {
                console.error('Update user error:', error);
                
                if (error.code === 11000) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Email already exists'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to update user profile'
                });
            }
        });

        // Deactivate account
        router.delete('/delete-me', this.protect.bind(this), async (req, res) => {
            try {
                await this.db.models.User.findByIdAndUpdate(req.user._id, { isActive: false });
                
                res.status(204).json({
                    status: 'success',
                    data: null
                });
                
            } catch (error) {
                console.error('Delete user error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to deactivate account'
                });
            }
        });

        return router;
    }

    // Patient Profile Routes
    getPatientRoutes(express) {
        const router = express.Router();
        
        // Protect all patient routes
        router.use(this.protect.bind(this));

        // Create patient profile
        router.post('/profile', async (req, res) => {
            try {
                const patientData = {
                    ...req.body,
                    // Sanitize string fields
                    fullName: this.sanitizeInput(req.body.fullName),
                    emergencyContact: {
                        name: this.sanitizeInput(req.body.emergencyContact?.name),
                        relationship: this.sanitizeInput(req.body.emergencyContact?.relationship),
                        phone: req.body.emergencyContact?.phone
                    }
                };
                
                const patient = await this.db.createPatientProfile(req.user._id, patientData);
                
                res.status(201).json({
                    status: 'success',
                    data: {
                        patient
                    }
                });
                
            } catch (error) {
                console.error('Create patient profile error:', error);
                
                if (error.message.includes('already exists')) {
                    return res.status(409).json({
                        status: 'fail',
                        message: 'Patient profile already exists'
                    });
                }
                
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to create patient profile'
                });
            }
        });

        // Get patient profile
        router.get('/profile', async (req, res) => {
            try {
                const patient = await this.db.models.Patient.findOne({ userId: req.user._id });
                
                if (!patient) {
                    return res.status(404).json({
                        status: 'fail',
                        message: 'Patient profile not found'
                    });
                }
                
                res.status(200).json({
                    status: 'success',
                    data: {
                        patient
                    }
                });
                
            } catch (error) {
                console.error('Get patient profile error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to fetch patient profile'
                });
            }
        });

        // Update patient profile
        router.patch('/profile', async (req, res) => {
            try {
                const patient = await this.db.models.Patient.findOneAndUpdate(
                    { userId: req.user._id },
                    req.body,
                    { new: true, runValidators: true }
                );
                
                if (!patient) {
                    return res.status(404).json({
                        status: 'fail',
                        message: 'Patient profile not found'
                    });
                }
                
                res.status(200).json({
                    status: 'success',
                    data: {
                        patient
                    }
                });
                
            } catch (error) {
                console.error('Update patient profile error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to update patient profile'
                });
            }
        });

        // Get patient history
        router.get('/history', async (req, res) => {
            try {
                const patient = await this.db.models.Patient.findOne({ userId: req.user._id });
                
                if (!patient) {
                    return res.status(404).json({
                        status: 'fail',
                        message: 'Patient profile not found'
                    });
                }
                
                const history = await this.db.getPatientHistory(patient._id);
                
                res.status(200).json({
                    status: 'success',
                    data: history
                });
                
            } catch (error) {
                console.error('Get patient history error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to fetch patient history'
                });
            }
        });

        return router;
    }

    // Appointment Routes
    getAppointmentRoutes(express) {
        const router = express.Router();
        
        // Protect all appointment routes
        router.use(this.protect.bind(this));

        // Create appointment
        router.post('/', async (req, res) => {
            try {
                const patient = await this.db.models.Patient.findOne({ userId: req.user._id });
                
                if (!patient) {
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Please create patient profile first'
                    });
                }
                
                const appointmentData = {
                    ...req.body,
                    patientId: patient._id
                };
                
                const appointment = await this.db.createAppointment(appointmentData);
                
                res.status(201).json({
                    status: 'success',
                    data: {
                        appointment
                    }
                });
                
            } catch (error) {
                console.error('Create appointment error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to create appointment'
                });
            }
        });

        // Get user appointments
        router.get('/', async (req, res) => {
            try {
                const patient = await this.db.models.Patient.findOne({ userId: req.user._id });
                
                if (!patient) {
                    return res.status(404).json({
                        status: 'fail',
                        message: 'Patient profile not found'
                    });
                }
                
                const appointments = await this.db.models.Appointment
                    .find({ patientId: patient._id })
                    .sort({ createdAt: -1 });
                
                res.status(200).json({
                    status: 'success',
                    results: appointments.length,
                    data: {
                        appointments
                    }
                });
                
            } catch (error) {
                console.error('Get appointments error:', error);
                res.status(500).json({
                    status: 'error',
                    message: 'Failed to fetch appointments'
                });
            }
        });

        return router;
    }
}

module.exports = AuthenticationManager;