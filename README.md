# MediCare AI Portal

A comprehensive healthcare web application that combines AI-powered symptom diagnosis with hospital locator services and appointment booking functionality.

## Overview

MediCare AI Portal is a full-stack web application designed to provide preliminary medical assistance through machine learning-based symptom analysis. The system helps users identify potential health conditions based on their symptoms and connects them with nearby healthcare facilities.

**⚠️ Medical Disclaimer**: This application is for educational and informational purposes only. It should NOT be used as a substitute for professional medical advice, diagnosis, or treatment. Always consult with qualified healthcare professionals for medical concerns.

## Features

- **AI Symptom Diagnosis**: Machine learning-powered analysis of user symptoms
- **Hospital Locator**: Find nearby healthcare facilities with ratings and contact information
- **Appointment Booking**: Schedule appointments with healthcare providers
- **Responsive Web Interface**: Mobile-friendly design for accessibility
- **Real-time API**: RESTful API endpoints for seamless data exchange

## Technology Stack

### Backend
- **Node.js** (v14 or higher) - Server runtime environment
- **Express.js** - Web application framework
- **Python** (v3.7 or higher) - Machine learning components
- **scikit-learn** - Machine learning algorithms
- **pandas** - Data manipulation and analysis
- **joblib** - Model serialization
- **fuzzywuzzy** - Fuzzy string matching for symptom recognition

### Frontend
- **HTML5** - Markup structure
- **CSS3** - Styling and responsive design
- **JavaScript (ES6+)** - Client-side functionality
- **Fetch API** - HTTP requests

### Machine Learning
- **Random Forest Classifier** - Primary disease prediction model
- **TF-IDF Vectorization** - Text feature extraction
- **Label Encoding** - Categorical data processing

## Dataset

The project uses the "Disease and Symptoms Dataset" from Kaggle:
- **Source**: [Kaggle Dataset - Disease and Symptoms](https://www.kaggle.com/datasets/choongqianzheng/disease-and-symptoms-dataset)
- **Description**: Contains symptom patterns and corresponding diseases for training the ML model
- **Format**: CSV files with symptom columns and disease labels
- **Size**: Multiple diseases with associated symptoms and precautionary measures

## Project Structure

```
MediCare-AI-Portal/
├── server.js                 # Main Express server
├── predict_api.py            # Python API for ML predictions
├── model_utils.py            # ML utility functions
├── train.py                  # Model training script
├── package.json              # Node.js dependencies
├── requirements.txt          # Python dependencies
├── website/
│   └── index.html           # Frontend web interface
├── data/
│   ├── symptom.csv          # Training dataset
│   └── precaution.csv       # Disease precautions
├── saved_models/
│   ├── model.joblib         # Trained ML model
│   ├── train_columns.joblib # Feature columns
│   └── label_encoder.joblib # Label encoder
└── README.md
```

## Installation and Setup

### Prerequisites

Ensure you have the following installed:
- Node.js (v14 or higher)
- Python (v3.7 or higher)
- npm or yarn package manager
- pip (Python package manager)

### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd MediCare-AI-Portal
```

### Step 2: Install Node.js Dependencies

```bash
npm install
```

Required packages:
- express
- cors
- path
- fs

### Step 3: Install Python Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` doesn't exist, install manually:
```bash
pip install pandas scikit-learn joblib fuzzywuzzy numpy python-Levenshtein
```

### Step 4: Download and Prepare Dataset

1. Download the dataset from [Kaggle](https://www.kaggle.com/datasets/choongqianzheng/disease-and-symptoms-dataset)
2. Create a `data/` folder in the project root
3. Place the following files in the `data/` folder:
   - `symptom.csv` - Main training data
   - `precaution.csv` - Disease precautions data

### Step 5: Train the Machine Learning Model

```bash
python train.py
```

This will:
- Load and preprocess the dataset
- Train the Random Forest model
- Save the model files in `saved_models/`
- Display training accuracy and model information

### Step 6: Test the AI Service

Test the Python prediction API:
```bash
python predict_api.py '["fever", "cough", "headache"]'
```

Expected output: JSON response with disease prediction and precautions

### Step 7: Start the Server

```bash
npm start
# or
node server.js
```

The server will start on `http://localhost:3000`

## API Endpoints

### Health Check
```http
GET /health
```
Returns server status and service availability.

### AI Diagnosis
```http
POST /api/predict
Content-Type: application/json

{
  "symptoms": ["fever", "cough", "headache"]
}
```

Response:
```json
{
  "disease": "Common Cold",
  "confidence": 85.6,
  "precautions": [
    "Rest and stay hydrated",
    "Take over-the-counter pain relievers",
    "Consult a doctor if symptoms persist"
  ],
  "needMoreInfo": false,
  "confidenceLevel": "high"
}
```

### Hospital Locator
```http
GET /api/hospitals?lat=12.9716&lng=77.5946&radius=5000
```

### Appointment Booking
```http
POST /api/appointments
Content-Type: application/json

{
  "patientName": "John Doe",
  "hospitalId": "hosp_001",
  "date": "2024-01-15",
  "time": "10:00",
  "symptoms": "fever, headache"
}
```

### Test AI Service
```http
GET /api/test-ai
```

## Usage

1. **Access the Web Interface**: Open `http://localhost:3000` in your browser
2. **Enter Symptoms**: Type your symptoms in the input field (comma-separated)
3. **Get AI Diagnosis**: Click "Analyze Symptoms" to receive AI-powered predictions
4. **Find Hospitals**: Use the hospital locator to find nearby healthcare facilities
5. **Book Appointment**: Schedule appointments with selected hospitals

## Model Performance

The Random Forest classifier achieves:
- **Training Accuracy**: ~95-98%
- **Test Accuracy**: ~85-90%
- **Prediction Time**: <1 second
- **Supported Diseases**: 40+ common conditions

## Troubleshooting

### Common Issues

1. **"Python script not found" error**
   - Ensure `predict_api.py` is in the project root
   - Verify Python is installed and accessible via command line

2. **"Invalid AI response format" error**
   - Check that model files exist in `saved_models/`
   - Run `python train.py` to generate model files
   - Verify dataset files are in `data/` folder

3. **Module import errors**
   - Install Python dependencies: `pip install -r requirements.txt`
   - Check Python version compatibility (3.7+)

4. **Low prediction confidence**
   - Ensure symptoms are spelled correctly
   - Try more specific symptom descriptions
   - Add additional related symptoms

### Debug Mode

Enable detailed logging by setting environment variable:
```bash
NODE_ENV=development node server.js
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and test thoroughly
4. Commit changes: `git commit -m "Add feature description"`
5. Push to branch: `git push origin feature-name`
6. Submit a pull request

## License

This project is intended for educational purposes. Please ensure compliance with medical software regulations if adapting for production use.

## Acknowledgments

- Dataset provided by Kaggle user choongqianzheng
- Built with open-source technologies
- Inspired by the need for accessible healthcare information

## Contact

For questions, issues, or contributions, please create an issue in the repository or contact the development team.

---

**Remember**: This application provides preliminary information only and should never replace professional medical consultation. Always seek qualified medical advice for health concerns.