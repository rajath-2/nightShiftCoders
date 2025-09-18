import pandas as pd
import joblib
import os
from fuzzywuzzy import process
import numpy as np

# Get absolute base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Build absolute paths
MODEL_PATH = os.path.join(BASE_DIR, "saved_models", "model.joblib")
COLUMNS_PATH = os.path.join(BASE_DIR, "saved_models", "train_columns.joblib")
PRECAUTION_PATH = os.path.join(BASE_DIR, "data", "precaution.csv")

def check_files_exist():
    """Check if all required files exist."""
    missing_files = []
    
    if not os.path.exists(MODEL_PATH):
        missing_files.append(f"Model file: {MODEL_PATH}")
    
    if not os.path.exists(COLUMNS_PATH):
        missing_files.append(f"Columns file: {COLUMNS_PATH}")
    
    if not os.path.exists(PRECAUTION_PATH):
        missing_files.append(f"Precautions file: {PRECAUTION_PATH}")
    
    if missing_files:
        error_msg = "Missing required files:\n" + "\n".join(missing_files)
        error_msg += "\n\nSolutions:"
        error_msg += "\n1. Run train.py first to generate model files"
        error_msg += "\n2. Make sure precaution.csv is in the data/ folder"
        raise FileNotFoundError(error_msg)

# Check files and load models
try:
    check_files_exist()
    print("All required files found")
    
    clf = joblib.load(MODEL_PATH)
    train_columns = joblib.load(COLUMNS_PATH)
    
    print(f"Model loaded successfully")
    print(f"Model can predict {len(clf.classes_)} diseases")
    print(f"Model expects {len(train_columns)} features")
    
    # Try to load precautions
    try:
        precaution_df = pd.read_csv(PRECAUTION_PATH)
        print(f"Precautions data loaded: {precaution_df.shape[0]} diseases")
    except Exception as e:
        print(f"Warning: Could not load precautions: {e}")
        precaution_df = pd.DataFrame()
        
except Exception as e:
    print(f"Error during initialization: {e}")
    raise

def normalize_symptom(s: str) -> str:
    """Normalize symptom strings for matching."""
    if not s or pd.isna(s):
        return ""
    return s.strip().lower().replace(" ", "_").replace("-", "_").replace("(", "").replace(")", "")

def fuzzy_symptom_match(user_symptoms):
    """Match user input symptoms to training columns with fuzzy logic."""
    matched = []
    match_details = []
    
    print(f"Matching {len(user_symptoms)} user symptoms...")
    
    for s in user_symptoms:
        if not s or not s.strip():
            continue
            
        s_norm = normalize_symptom(s)
        print(f"  Looking for: '{s}' -> normalized: '{s_norm}'")
        
        # Try exact match first
        if s_norm in train_columns:
            matched.append(s_norm)
            match_details.append(f"  Exact match: '{s}' -> '{s_norm}'")
        else:
            # Try fuzzy match
            try:
                match, score = process.extractOne(s_norm, train_columns)
                print(f"    Best fuzzy match: '{match}' (score: {score})")
                
                if score >= 70:  # Threshold for accepting matches
                    matched.append(match)
                    match_details.append(f"  Fuzzy match: '{s}' -> '{match}' (score: {score})")
                else:
                    match_details.append(f"  No good match: '{s}' (best: '{match}', score: {score})")
            except Exception as e:
                match_details.append(f"  Error matching '{s}': {e}")
    
    print("\nMatching results:")
    for detail in match_details:
        print(detail)
    
    print(f"\nSuccessfully matched {len(matched)} symptoms: {matched}")
    return matched

def predict_disease(symptoms_list):
    """Predict disease from symptoms with confidence score."""
    try:
        print(f"\nPredicting disease for symptoms: {symptoms_list}")
        
        # Handle empty input
        if not symptoms_list:
            return "Unknown", 0.0
        
        # Clean and filter symptoms
        symptoms_list = [s.strip() for s in symptoms_list if s and s.strip()]
        
        if not symptoms_list:
            return "Unknown", 0.0
        
        # Match symptoms to training features
        matched_symptoms = fuzzy_symptom_match(symptoms_list)
        
        if not matched_symptoms:
            print("No symptoms could be matched to training data")
            return "Unknown", 0.0
        
        # Create input vector
        input_dict = {col: 0 for col in train_columns}
        for symptom in matched_symptoms:
            if symptom in input_dict:
                input_dict[symptom] = 1
        
        # Convert to DataFrame
        X_input = pd.DataFrame([input_dict])
        print(f"Input vector created with {sum(input_dict.values())} active features")
        
        # Get predictions
        probs = clf.predict_proba(X_input)[0]
        disease_idx = np.argmax(probs)
        disease = clf.classes_[disease_idx]
        confidence = probs[disease_idx]
        
        print(f"Prediction: {disease} (confidence: {confidence:.3f})")
        
        # Show top 3 predictions for debugging
        top_indices = np.argsort(probs)[-3:][::-1]
        print("Top 3 predictions:")
        for i, idx in enumerate(top_indices, 1):
            print(f"  {i}. {clf.classes_[idx]}: {probs[idx]:.3f}")
        
        return disease, confidence
        
    except Exception as e:
        print(f"Error in predict_disease: {e}")
        return "Error", 0.0

def get_precautions(disease):
    """Return precaution list for a given disease."""
    try:
        if precaution_df.empty:
            print("No precaution data available")
            return []
        
        print(f"Looking for precautions for: {disease}")
        
        # Try exact match first
        row = precaution_df[precaution_df["Disease"].str.strip().str.lower() == disease.strip().lower()]
        
        if row.empty:
            print(f"No precautions found for '{disease}'")
            print(f"Available diseases: {precaution_df['Disease'].tolist()}")
            return []
        
        # Get precaution columns (exclude Disease column)
        precaution_cols = [col for col in row.columns if col.lower() != "disease"]
        
        precautions = []
        for col in precaution_cols:
            value = row.iloc[0][col]
            if pd.notna(value) and str(value).strip() and str(value).strip().lower() != 'nan':
                precautions.append(str(value).strip())
        
        print(f"Found {len(precautions)} precautions")
        return precautions
        
    except Exception as e:
        print(f"Error getting precautions: {e}")
        return []

# Test function
def test_prediction():
    """Test the prediction system with sample data."""
    test_symptoms = ["fever", "cough", "headache"]
    print(f"Testing with symptoms: {test_symptoms}")
    
    try:
        disease, confidence = predict_disease(test_symptoms)
        precautions = get_precautions(disease)
        
        print(f"Test result:")
        print(f"  Disease: {disease}")
        print(f"  Confidence: {confidence:.3f}")
        print(f"  Precautions: {precautions}")
        
        return True
    except Exception as e:
        print(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    test_prediction()