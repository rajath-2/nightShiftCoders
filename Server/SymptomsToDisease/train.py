import os
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# File paths
DATA_PATH = os.path.join("data", "symptom.csv")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "saved_models")
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
COLUMNS_PATH = os.path.join(MODEL_DIR, "train_columns.joblib")
LABEL_ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.joblib")

def normalize_symptom(symptom):
    """Normalize symptom names for consistency."""
    if pd.isna(symptom) or not symptom.strip():
        return None
    return symptom.strip().lower().replace(" ", "_").replace("-", "_").replace("(", "").replace(")", "")

def load_data():
    try:
        df = pd.read_csv(DATA_PATH)
        print(f"✅ Loaded data with shape: {df.shape}")
        print(f"✅ Columns: {list(df.columns)}")
        
        # Check if symptom columns exist
        symptom_cols = [col for col in df.columns if col.lower().startswith("symptom")]
        
        if symptom_cols:
            print(f"✅ Found symptom columns: {symptom_cols}")
            # Create binary features from symptom columns
            all_symptoms = set()
            
            # Collect all unique symptoms
            for col in symptom_cols:
                symptoms_in_col = df[col].dropna().apply(normalize_symptom).dropna()
                all_symptoms.update(symptoms_in_col)
            
            all_symptoms = sorted([s for s in all_symptoms if s])
            print(f"✅ Found {len(all_symptoms)} unique symptoms")
            
            # Create binary matrix
            X = pd.DataFrame(0, index=df.index, columns=all_symptoms)
            
            for col in symptom_cols:
                for idx, val in df[col].items():
                    normalized_val = normalize_symptom(val)
                    if normalized_val and normalized_val in all_symptoms:
                        X.at[idx, normalized_val] = 1
            
            # Handle target variable
            if "Disease" in df.columns:
                y = df["Disease"].str.strip()
            elif "disease" in df.columns:
                y = df["disease"].str.strip()
            else:
                raise ValueError("No 'Disease' column found in the dataset")
            
        else:
            # Assume data is already preprocessed
            print("✅ No symptom columns found, assuming preprocessed data")
            if "Disease" in df.columns:
                X = df.drop("Disease", axis=1)
                y = df["Disease"]
            elif "disease" in df.columns:
                X = df.drop("disease", axis=1)
                y = df["disease"]
            else:
                raise ValueError("No 'Disease' column found in the dataset")
        
        # Remove any remaining missing values
        X = X.fillna(0)
        y = y.dropna()
        X = X.loc[y.index]  # Align indices
        
        print(f"✅ Final feature matrix shape: {X.shape}")
        print(f"✅ Number of unique diseases: {y.nunique()}")
        
        # Save feature columns
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(X.columns.tolist(), COLUMNS_PATH)
        
        return X, y
        
    except FileNotFoundError:
        print(f"❌ Error: File {DATA_PATH} not found!")
        print("Make sure the symptom.csv file is in the 'data' folder")
        raise
    except Exception as e:
        print(f"❌ Error loading data: {str(e)}")
        raise

def train_model():
    try:
        X, y = load_data()
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"✅ Training set size: {X_train.shape[0]}")
        print(f"✅ Test set size: {X_test.shape[0]}")
        
        # Train the model
        clf = RandomForestClassifier(
            n_estimators=100, 
            random_state=42,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )
        
        print("🔄 Training model...")
        clf.fit(X_train, y_train)
        
        # Calculate accuracies
        train_acc = clf.score(X_train, y_train)
        test_acc = clf.score(X_test, y_test)
        
        # Save the model
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(clf, MODEL_PATH)
        
        print(f"✅ Model trained and saved at: {MODEL_PATH}")
        print(f"✅ Train accuracy: {train_acc:.3f}")
        print(f"✅ Test accuracy: {test_acc:.3f}")
        print(f"✅ Feature columns saved at: {COLUMNS_PATH}")
        
        # Print some model info
        print(f"✅ Model can predict {len(clf.classes_)} different diseases")
        print(f"✅ Top 10 most important features:")
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': clf.feature_importances_
        }).sort_values('importance', ascending=False)
        print(feature_importance.head(10))
        
        return clf
        
    except Exception as e:
        print(f"❌ Error training model: {str(e)}")
        raise

if __name__ == "__main__":
    train_model()