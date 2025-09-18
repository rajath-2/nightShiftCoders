import sys
import json
import traceback
import model_utils

def predict_symptoms(symptoms):
    """Main prediction function."""
    try:
        print(f"Received symptoms: {symptoms}", file=sys.stderr)
        
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
        
        print(f"Cleaned symptoms: {cleaned_symptoms}", file=sys.stderr)
        
        # Get disease prediction
        disease, confidence = model_utils.predict_disease(cleaned_symptoms)
        
        print(f"Prediction result: {disease} (confidence: {confidence})", file=sys.stderr)
        
        # Get precautions
        try:
            precautions = model_utils.get_precautions(disease)
            print(f"Found {len(precautions)} precautions for {disease}", file=sys.stderr)
            if not precautions:
                precautions = [
                    "Rest and stay hydrated",
                    "Monitor symptoms closely", 
                    "Consult a healthcare professional if symptoms worsen",
                    "Maintain good hygiene"
                ]
                print(f"No specific precautions found, using general advice", file=sys.stderr)
        except Exception as e:
            print(f"Error getting precautions: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            precautions = [
                "Consult a healthcare professional",
                "Rest and stay hydrated",
                "Monitor symptoms closely"
            ]
        
        # Determine if more info is needed
        need_more_info = confidence < 0.4 or disease == "Unknown"
        
        result = {
            "disease": str(disease),
            "confidence": float(round(confidence * 100, 2)),  # Convert to percentage and ensure it's Python float
            "precautions": precautions if precautions else ["Consult a healthcare professional"],
            "needMoreInfo": bool(need_more_info)  # Ensure it's Python bool, not numpy bool
        }
        
        print(f"Final result: {result}", file=sys.stderr)
        return result
        
    except Exception as e:
        error_msg = f"Error in predict_symptoms: {str(e)}"
        print(f"❌ {error_msg}", file=sys.stderr)
        print(f"❌ Traceback: {traceback.format_exc()}", file=sys.stderr)
        
        return {
            "disease": "Error",
            "confidence": 0.0,
            "precautions": ["System error occurred. Please try again."],
            "needMoreInfo": True,
            "error": error_msg
        }

if __name__ == "__main__":
    try:
        print("Starting prediction API...", file=sys.stderr)
        
        # Check if symptoms were passed
        if len(sys.argv) < 2:
            result = {
                "error": "No symptoms provided in command line arguments",
                "disease": "Unknown",
                "confidence": 0.0,
                "precautions": [],
                "needMoreInfo": True
            }
        else:
            # Parse symptoms from command line
            try:
                symptoms_json = sys.argv[1]
                print(f"Raw input: '{symptoms_json}'", file=sys.stderr)
                print(f"Input length: {len(symptoms_json)}", file=sys.stderr)
                
                # Handle different input formats
                symptoms = None
                
                # Try JSON parsing first
                try:
                    if symptoms_json.startswith('[') and symptoms_json.endswith(']'):
                        symptoms = json.loads(symptoms_json)
                        print(f"Parsed as JSON array", file=sys.stderr)
                    else:
                        raise json.JSONDecodeError("Not JSON format", symptoms_json, 0)
                except json.JSONDecodeError:
                    print(f"Not JSON format, parsing as comma-separated", file=sys.stderr)
                    # Parse as comma-separated string
                    symptoms = symptoms_json.strip().split(',')
                    symptoms = [s.strip().strip('"').strip("'") for s in symptoms if s.strip()]
                    print(f"Parsed as comma-separated", file=sys.stderr)
                
                print(f"Final parsed symptoms: {symptoms}", file=sys.stderr)
                
                # Run prediction
                result = predict_symptoms(symptoms)
                
            except json.JSONDecodeError as e:
                print(f"❌ JSON parsing error: {e}", file=sys.stderr)
                result = {
                    "error": f"Invalid JSON format: {str(e)}",
                    "disease": "Error",
                    "confidence": 0.0,
                    "precautions": [],
                    "needMoreInfo": True
                }
            except Exception as e:
                print(f"❌ Unexpected error: {e}", file=sys.stderr)
                print(f"❌ Traceback: {traceback.format_exc()}", file=sys.stderr)
                result = {
                    "error": f"Unexpected error: {str(e)}",
                    "disease": "Error", 
                    "confidence": 0.0,
                    "precautions": [],
                    "needMoreInfo": True
                }
        
        # Output result as JSON
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        # Last resort error handling
        error_result = {
            "error": f"Critical error: {str(e)}",
            "disease": "System Error",
            "confidence": 0.0,
            "precautions": ["System is currently unavailable"],
            "needMoreInfo": True
        }
        print(json.dumps(error_result))