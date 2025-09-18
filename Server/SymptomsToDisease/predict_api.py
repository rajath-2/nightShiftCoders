import sys
import json
import traceback
import os

# Redirect all debugging output to stderr to keep stdout clean for JSON
def debug_print(msg):
    print(msg, file=sys.stderr)

try:
    import model_utils
    debug_print("Model utils imported successfully")
except ImportError as e:
    debug_print(f"Failed to import model_utils: {e}")
    # Exit with error JSON
    error_result = {
        "error": "Missing required modules",
        "disease": "System Error",
        "confidence": 0.0,
        "precautions": ["AI service is currently unavailable"],
        "needMoreInfo": True
    }
    print(json.dumps(error_result))
    sys.exit(1)

def predict_symptoms(symptoms):
    """Main prediction function."""
    try:
        debug_print(f"Received symptoms: {symptoms}")
        
        # Validate input
        if not symptoms:
            return {
                "disease": "Unknown",
                "confidence": 0.0,
                "precautions": ["Please provide symptoms for diagnosis"],
                "needMoreInfo": True,
                "error": "No symptoms provided"
            }
        
        # Clean symptoms list
        cleaned_symptoms = []
        for symptom in symptoms:
            if symptom and isinstance(symptom, str) and symptom.strip():
                cleaned_symptoms.append(symptom.strip())
        
        if not cleaned_symptoms:
            return {
                "disease": "Unknown",
                "confidence": 0.0,
                "precautions": ["Please provide valid symptoms for diagnosis"],
                "needMoreInfo": True,
                "error": "No valid symptoms provided"
            }
        
        debug_print(f"Cleaned symptoms: {cleaned_symptoms}")
        
        # Get disease prediction
        disease, confidence = model_utils.predict_disease(cleaned_symptoms)
        
        debug_print(f"Prediction result: {disease} (confidence: {confidence})")
        
        # Get precautions
        try:
            precautions = model_utils.get_precautions(disease)
            debug_print(f"Found {len(precautions)} precautions for {disease}")
            if not precautions:
                precautions = [
                    "Rest and stay hydrated",
                    "Monitor symptoms closely", 
                    "Consult a healthcare professional if symptoms worsen",
                    "Maintain good hygiene"
                ]
                debug_print(f"No specific precautions found, using general advice")
        except Exception as e:
            debug_print(f"Error getting precautions: {e}")
            precautions = [
                "Consult a healthcare professional",
                "Rest and stay hydrated",
                "Monitor symptoms closely"
            ]
        
        # Determine if more info is needed
        need_more_info = confidence < 0.4 or disease == "Unknown"
        
        # Ensure all values are JSON serializable
        result = {
            "disease": str(disease),
            "confidence": float(round(confidence * 100, 2)),  # Convert to percentage
            "precautions": precautions if precautions else ["Consult a healthcare professional"],
            "needMoreInfo": bool(need_more_info)
        }
        
        debug_print(f"Final result: {result}")
        return result
        
    except Exception as e:
        error_msg = f"Error in predict_symptoms: {str(e)}"
        debug_print(f"❌ {error_msg}")
        debug_print(f"❌ Traceback: {traceback.format_exc()}")
        
        return {
            "disease": "Error",
            "confidence": 0.0,
            "precautions": ["System error occurred. Please try again."],
            "needMoreInfo": True,
            "error": error_msg
        }

if __name__ == "__main__":
    try:
        debug_print("Starting prediction API...")
        
        # Check if symptoms were passed
        if len(sys.argv) < 2:
            result = {
                "error": "No symptoms provided in command line arguments",
                "disease": "Unknown",
                "confidence": 0.0,
                "precautions": ["Please provide symptoms for analysis"],
                "needMoreInfo": True
            }
        else:
            # Parse symptoms from command line
            try:
                symptoms_json = sys.argv[1]
                debug_print(f"Raw input: '{symptoms_json}'")
                debug_print(f"Input length: {len(symptoms_json)}")
                
                # Handle different input formats
                symptoms = None
                
                # Try JSON parsing first
                try:
                    if symptoms_json.startswith('[') and symptoms_json.endswith(']'):
                        symptoms = json.loads(symptoms_json)
                        debug_print(f"Parsed as JSON array")
                    else:
                        raise json.JSONDecodeError("Not JSON format", symptoms_json, 0)
                except json.JSONDecodeError:
                    debug_print(f"Not JSON format, parsing as comma-separated")
                    # Parse as comma-separated string
                    symptoms = symptoms_json.strip().split(',')
                    symptoms = [s.strip().strip('"').strip("'") for s in symptoms if s.strip()]
                    debug_print(f"Parsed as comma-separated")
                
                debug_print(f"Final parsed symptoms: {symptoms}")
                
                # Run prediction
                result = predict_symptoms(symptoms)
                
            except json.JSONDecodeError as e:
                debug_print(f"❌ JSON parsing error: {e}")
                result = {
                    "error": f"Invalid JSON format: {str(e)}",
                    "disease": "Error",
                    "confidence": 0.0,
                    "precautions": ["Invalid input format"],
                    "needMoreInfo": True
                }
            except Exception as e:
                debug_print(f"❌ Unexpected error: {e}")
                debug_print(f"❌ Traceback: {traceback.format_exc()}")
                result = {
                    "error": f"Unexpected error: {str(e)}",
                    "disease": "Error", 
                    "confidence": 0.0,
                    "precautions": ["System error occurred"],
                    "needMoreInfo": True
                }
        
        # Output result as JSON to stdout ONLY
        # No other print statements should go to stdout
        print(json.dumps(result, ensure_ascii=False))
        
    except Exception as e:
        # Last resort error handling
        error_result = {
            "error": f"Critical error: {str(e)}",
            "disease": "System Error",
            "confidence": 0.0,
            "precautions": ["System is currently unavailable"],
            "needMoreInfo": True
        }
        print(json.dumps(error_result, ensure_ascii=False))