// database.js - Secure Database Implementation
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// MongoDB Connection with Security Options
class DatabaseManager {
    constructor() {
        this.connection = null;
        this.models = {};
    }

    async connect(connectionString) {
        try {
            this.connection = await mongoose.connect(connectionString, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                serverSelectionTimeoutMS: 5000,
                maxPoolSize: 10,
                bufferMaxEntries: 0,
                // Security options
                ssl: process.env.NODE_ENV === 'production',
                authSource: 'admin'
            });
            
            console.log('Database connected successfully');
            this.setupModels();
            return this.connection;
        } catch (error) {
            console.error('Database connection failed:', error);
            throw error;
        }
    }

    setupModels() {
        // User Schema with Security Features
        const userSchema = new mongoose.Schema({
            email: {
                type: String,
                required: [true, 'Email is required'],
                unique: true,
                lowercase: true,
                validate: {
                    validator: validator.isEmail,
                    message: 'Please provide a valid email'
                }
            },
            password: {
                type: String,
                required: [true, 'Password is required'],
                minlength: [8, 'Password must be at least 8 characters'],
                select: false // Don't include password in queries by default
            },
            isEmailVerified: {
                type: Boolean,
                default: false
            },
            emailVerificationToken: {
                type: String,
                select: false
            },
            emailVerificationExpires: {
                type: Date,
                select: false
            },
            passwordResetToken: {
                type: String,
                select: false
            },
            passwordResetExpires: {
                type: Date,
                select: false
            },
            loginAttempts: {
                type: Number,
                default: 0,
                select: false
            },
            lockUntil: {
                type: Date,
                select: false
            },
            lastLogin: {
                type: Date
            },
            role: {
                type: String,
                enum: ['patient', 'doctor', 'admin'],
                default: 'patient'
            },
            isActive: {
                type: Boolean,
                default: true
            },
            twoFactorEnabled: {
                type: Boolean,
                default: false
            },
            twoFactorSecret: {
                type: String,
                select: false
            },
            createdAt: {
                type: Date,
                default: Date.now
            },
            updatedAt: {
                type: Date,
                default: Date.now
            }
        }, {
            timestamps: true,
            toJSON: { 
                transform: function(doc, ret) {
                    delete ret.password;
                    delete ret.__v;
                    return ret;
                }
            }
        });

        // Patient Profile Schema
        const patientSchema = new mongoose.Schema({
            userId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                required: true,
                unique: true
            },
            fullName: {
                type: String,
                required: [true, 'Full name is required'],
                trim: true,
                maxlength: [100, 'Name cannot exceed 100 characters']
            },
            dateOfBirth: {
                type: Date,
                validate: {
                    validator: function(date) {
                        return date < new Date();
                    },
                    message: 'Date of birth must be in the past'
                }
            },
            gender: {
                type: String,
                enum: ['male', 'female', 'other', 'prefer-not-to-say'],
                required: true
            },
            bloodGroup: {
                type: String,
                enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'],
                required: true
            },
            phone: {
                type: String,
                validate: {
                    validator: function(phone) {
                        return validator.isMobilePhone(phone, 'any');
                    },
                    message: 'Please provide a valid phone number'
                }
            },
            emergencyContact: {
                name: {
                    type: String,
                    required: true
                },
                relationship: {
                    type: String,
                    required: true
                },
                phone: {
                    type: String,
                    required: true,
                    validate: {
                        validator: function(phone) {
                            return validator.isMobilePhone(phone, 'any');
                        },
                        message: 'Please provide a valid emergency contact phone'
                    }
                }
            },
            address: {
                street: String,
                city: String,
                state: String,
                zipCode: String,
                country: {
                    type: String,
                    default: 'India'
                }
            },
            medicalHistory: [{
                condition: String,
                diagnosedDate: Date,
                status: {
                    type: String,
                    enum: ['active', 'resolved', 'chronic']
                }
            }],
            allergies: [{
                allergen: String,
                severity: {
                    type: String,
                    enum: ['mild', 'moderate', 'severe']
                },
                reaction: String
            }],
            currentMedications: [{
                name: String,
                dosage: String,
                frequency: String,
                startDate: Date
            }],
            doctorPreference: {
                type: String,
                enum: ['male', 'female', 'any'],
                default: 'any'
            },
            insuranceInfo: {
                provider: String,
                policyNumber: String,
                groupNumber: String
            },
            privacySettings: {
                shareDataForResearch: {
                    type: Boolean,
                    default: false
                },
                allowMarketing: {
                    type: Boolean,
                    default: false
                }
            }
        }, {
            timestamps: true
        });

        // AI Diagnosis History Schema
        const diagnosisHistorySchema = new mongoose.Schema({
            userId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'User',
                required: true
            },
            patientId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Patient',
                required: true
            },
            symptoms: [{
                type: String,
                required: true
            }],
            aiDiagnosis: {
                disease: {
                    type: String,
                    required: true
                },
                confidence: {
                    type: Number,
                    required: true,
                    min: 0,
                    max: 100
                },
                precautions: [String]
            },
            doctorVerification: {
                verified: {
                    type: Boolean,
                    default: false
                },
                doctorId: {
                    type: mongoose.Schema.Types.ObjectId,
                    ref: 'User'
                },
                actualDiagnosis: String,
                notes: String,
                verifiedAt: Date
            },
            appointmentId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Appointment'
            }
        }, {
            timestamps: true
        });

        // Appointment Schema
        const appointmentSchema = new mongoose.Schema({
            appointmentId: {
                type: String,
                unique: true,
                required: true
            },
            patientId: {
                type: mongoose.Schema.Types.ObjectId,
                ref: 'Patient',
                required: true
            },
            doctorId: {
                type: String, // This could be expanded to reference a Doctor model
                required: true
            },
            doctorName: {
                type: String,
                required: true
            },
            specialty: {
                type: String,
                required: true
            },
            appointmentDate: {
                type: Date,
                required: true,
                validate: {
                    validator: function(date) {
                        return date >= new Date();
                    },
                    message: 'Appointment date must be in the future'
                }
            },
            appointmentTime: {
                type: String,
                required: true
            },
            duration: {
                type: Number,
                default: 30 // minutes
            },
            status: {
                type: String,
                enum: ['scheduled', 'confirmed', 'completed', 'cancelled', 'no-show'],
                default: 'scheduled'
            },
            symptoms: [String],
            aiPreAssessment: {
                disease: String,
                confidence: Number,
                precautions: [String]
            },
            doctorNotes: {
                diagnosis: String,
                prescription: String,
                followUp: Date,
                notes: String
            },
            paymentInfo: {
                amount: Number,
                currency: {
                    type: String,
                    default: 'INR'
                },
                status: {
                    type: String,
                    enum: ['pending', 'paid', 'failed', 'refunded'],
                    default: 'pending'
                },
                transactionId: String
            }
        }, {
            timestamps: true
        });

        // Security Middleware for User Schema
        userSchema.virtual('isLocked').get(function() {
            return !!(this.lockUntil && this.lockUntil > Date.now());
        });

        // Hash password before saving
        userSchema.pre('save', async function(next) {
            if (!this.isModified('password')) return next();
            
            try {
                const salt = await bcrypt.genSalt(12);
                this.password = await bcrypt.hash(this.password, salt);
                next();
            } catch (error) {
                next(error);
            }
        });

        // Update timestamp
        userSchema.pre('save', function(next) {
            this.updatedAt = new Date();
            next();
        });

        // Instance method to compare passwords
        userSchema.methods.comparePassword = async function(candidatePassword) {
            if (!this.password) return false;
            return bcrypt.compare(candidatePassword, this.password);
        };

        // Instance method to handle failed login attempts
        userSchema.methods.incrementLoginAttempts = async function() {
            // If we have a previous lock that has expired, restart at 1
            if (this.lockUntil && this.lockUntil < Date.now()) {
                return this.updateOne({
                    $unset: {
                        lockUntil: 1
                    },
                    $set: {
                        loginAttempts: 1
                    }
                });
            }
            
            const updates = { $inc: { loginAttempts: 1 } };
            
            // Lock account after 5 failed attempts for 2 hours
            if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
                updates.$set = {
                    lockUntil: Date.now() + 2 * 60 * 60 * 1000 // 2 hours
                };
            }
            
            return this.updateOne(updates);
        };

        // Instance method to reset login attempts
        userSchema.methods.resetLoginAttempts = async function() {
            return this.updateOne({
                $unset: {
                    loginAttempts: 1,
                    lockUntil: 1
                },
                $set: {
                    lastLogin: new Date()
                }
            });
        };

        // Generate password reset token
        userSchema.methods.createPasswordResetToken = function() {
            const resetToken = crypto.randomBytes(32).toString('hex');
            
            this.passwordResetToken = crypto
                .createHash('sha256')
                .update(resetToken)
                .digest('hex');
                
            this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
            
            return resetToken;
        };

        // Generate email verification token
        userSchema.methods.createEmailVerificationToken = function() {
            const verificationToken = crypto.randomBytes(32).toString('hex');
            
            this.emailVerificationToken = crypto
                .createHash('sha256')
                .update(verificationToken)
                .digest('hex');
                
            this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
            
            return verificationToken;
        };

        // Create indexes for performance and security
        userSchema.index({ email: 1 }, { unique: true });
        userSchema.index({ passwordResetToken: 1 });
        userSchema.index({ emailVerificationToken: 1 });
        patientSchema.index({ userId: 1 }, { unique: true });
        diagnosisHistorySchema.index({ userId: 1, createdAt: -1 });
        appointmentSchema.index({ patientId: 1, appointmentDate: 1 });
        appointmentSchema.index({ appointmentId: 1 }, { unique: true });

        // Create models
        this.models.User = mongoose.model('User', userSchema);
        this.models.Patient = mongoose.model('Patient', patientSchema);
        this.models.DiagnosisHistory = mongoose.model('DiagnosisHistory', diagnosisHistorySchema);
        this.models.Appointment = mongoose.model('Appointment', appointmentSchema);
    }

    // User management methods
    async createUser(userData) {
        try {
            // Validate input
            const { email, password } = userData;
            
            if (!validator.isEmail(email)) {
                throw new Error('Invalid email format');
            }
            
            if (!validator.isLength(password, { min: 8 })) {
                throw new Error('Password must be at least 8 characters long');
            }
            
            // Check if user already exists
            const existingUser = await this.models.User.findOne({ email });
            if (existingUser) {
                throw new Error('User already exists with this email');
            }
            
            // Create user
            const user = new this.models.User(userData);
            const verificationToken = user.createEmailVerificationToken();
            
            await user.save();
            
            return {
                user: user.toJSON(),
                verificationToken
            };
        } catch (error) {
            throw error;
        }
    }

    async authenticateUser(email, password) {
        try {
            // Find user and include password field
            const user = await this.models.User.findOne({ email }).select('+password +loginAttempts +lockUntil');
            
            if (!user) {
                throw new Error('Invalid credentials');
            }
            
            // Check if account is locked
            if (user.isLocked) {
                throw new Error('Account temporarily locked due to too many failed login attempts');
            }
            
            // Check if account is active
            if (!user.isActive) {
                throw new Error('Account has been deactivated');
            }
            
            // Compare password
            const isMatch = await user.comparePassword(password);
            
            if (!isMatch) {
                await user.incrementLoginAttempts();
                throw new Error('Invalid credentials');
            }
            
            // Reset login attempts on successful login
            await user.resetLoginAttempts();
            
            return user.toJSON();
        } catch (error) {
            throw error;
        }
    }

    async createPatientProfile(userId, patientData) {
        try {
            // Check if patient profile already exists
            const existingProfile = await this.models.Patient.findOne({ userId });
            if (existingProfile) {
                throw new Error('Patient profile already exists for this user');
            }
            
            const patient = new this.models.Patient({
                userId,
                ...patientData
            });
            
            await patient.save();
            return patient.toJSON();
        } catch (error) {
            throw error;
        }
    }

    async saveDiagnosisHistory(diagnosisData) {
        try {
            const diagnosis = new this.models.DiagnosisHistory(diagnosisData);
            await diagnosis.save();
            return diagnosis.toJSON();
        } catch (error) {
            throw error;
        }
    }

    async createAppointment(appointmentData) {
        try {
            // Generate unique appointment ID
            const appointmentId = 'APT' + Date.now() + Math.random().toString(36).substr(2, 9);
            
            const appointment = new this.models.Appointment({
                appointmentId,
                ...appointmentData
            });
            
            await appointment.save();
            return appointment.toJSON();
        } catch (error) {
            throw error;
        }
    }

    async getUserWithPatient(userId) {
        try {
            const user = await this.models.User.findById(userId);
            const patient = await this.models.Patient.findOne({ userId });
            
            return {
                user: user?.toJSON(),
                patient: patient?.toJSON()
            };
        } catch (error) {
            throw error;
        }
    }

    async getPatientHistory(patientId) {
        try {
            const [diagnoses, appointments] = await Promise.all([
                this.models.DiagnosisHistory.find({ patientId }).sort({ createdAt: -1 }),
                this.models.Appointment.find({ patientId }).sort({ createdAt: -1 })
            ]);
            
            return {
                diagnoses,
                appointments
            };
        } catch (error) {
            throw error;
        }
    }

    // Security utility methods
    async changePassword(userId, currentPassword, newPassword) {
        try {
            const user = await this.models.User.findById(userId).select('+password');
            
            if (!user) {
                throw new Error('User not found');
            }
            
            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) {
                throw new Error('Current password is incorrect');
            }
            
            user.password = newPassword;
            await user.save();
            
            return { message: 'Password updated successfully' };
        } catch (error) {
            throw error;
        }
    }

    async resetPassword(token, newPassword) {
        try {
            const hashedToken = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex');
                
            const user = await this.models.User.findOne({
                passwordResetToken: hashedToken,
                passwordResetExpires: { $gt: Date.now() }
            });
            
            if (!user) {
                throw new Error('Token is invalid or has expired');
            }
            
            user.password = newPassword;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            
            await user.save();
            
            return { message: 'Password reset successfully' };
        } catch (error) {
            throw error;
        }
    }

    async verifyEmail(token) {
        try {
            const hashedToken = crypto
                .createHash('sha256')
                .update(token)
                .digest('hex');
                
            const user = await this.models.User.findOne({
                emailVerificationToken: hashedToken,
                emailVerificationExpires: { $gt: Date.now() }
            });
            
            if (!user) {
                throw new Error('Token is invalid or has expired');
            }
            
            user.isEmailVerified = true;
            user.emailVerificationToken = undefined;
            user.emailVerificationExpires = undefined;
            
            await user.save();
            
            return { message: 'Email verified successfully' };
        } catch (error) {
            throw error;
        }
    }

    // Rate limiting for login attempts
    createLoginLimiter() {
        return rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: 5, // Limit each IP to 5 requests per windowMs
            message: 'Too many login attempts, please try again later',
            standardHeaders: true,
            legacyHeaders: false
        });
    }

    // Cleanup expired tokens
    async cleanupExpiredTokens() {
        try {
            const now = new Date();
            
            await this.models.User.updateMany(
                {
                    $or: [
                        { passwordResetExpires: { $lt: now } },
                        { emailVerificationExpires: { $lt: now } }
                    ]
                },
                {
                    $unset: {
                        passwordResetToken: 1,
                        passwordResetExpires: 1,
                        emailVerificationToken: 1,
                        emailVerificationExpires: 1
                    }
                }
            );
            
            console.log('Expired tokens cleaned up successfully');
        } catch (error) {
            console.error('Error cleaning up expired tokens:', error);
        }
    }

    async disconnect() {
        if (this.connection) {
            await mongoose.disconnect();
            console.log('Database disconnected');
        }
    }
}

module.exports = DatabaseManager;