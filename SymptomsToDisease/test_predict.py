#!/usr/bin/env python3
"""
Debug script to check precautions file and data
"""
import pandas as pd
import os

# Check file paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRECAUTION_PATH = os.path.join(BASE_DIR, "data", "precaution.csv")

print("🔍 DEBUGGING PRECAUTIONS")
print("=" * 50)

print(f"📁 Base directory: {BASE_DIR}")
print(f"📄 Precaution file path: {PRECAUTION_PATH}")
print(f"📋 File exists: {os.path.exists(PRECAUTION_PATH)}")

if os.path.exists(PRECAUTION_PATH):
    try:
        # Load the precautions file
        precaution_df = pd.read_csv(PRECAUTION_PATH)
        print(f"✅ Precautions loaded successfully")
        print(f"📊 Shape: {precaution_df.shape}")
        print(f"🏥 Columns: {list(precaution_df.columns)}")
        
        # Show first few rows
        print(f"\n📋 First 5 rows:")
        print(precaution_df.head())
        
        # Check Disease column
        if "Disease" in precaution_df.columns:
            diseases = precaution_df["Disease"].tolist()
            print(f"\n🏥 Found {len(diseases)} diseases:")
            for i, disease in enumerate(diseases[:10], 1):
                print(f"  {i}. {disease}")
            if len(diseases) > 10:
                print(f"  ... and {len(diseases) - 10} more")
                
        else:
            print(f"❌ No 'Disease' column found!")
            print(f"Available columns: {list(precaution_df.columns)}")
        
        # Test getting precautions for a specific disease
        print(f"\n🧪 Testing precaution lookup...")
        
        # Get first disease
        test_disease = precaution_df.iloc[0]["Disease"] if "Disease" in precaution_df.columns else None
        
        if test_disease:
            print(f"🔍 Looking for precautions for: '{test_disease}'")
            
            # Try exact match
            row = precaution_df[precaution_df["Disease"].str.strip().str.lower() == test_disease.strip().lower()]
            
            if not row.empty:
                print(f"✅ Found row for '{test_disease}'")
                
                # Get precaution columns
                precaution_cols = [col for col in row.columns if col.lower() != "disease"]
                print(f"📋 Precaution columns: {precaution_cols}")
                
                precautions = []
                for col in precaution_cols:
                    value = row.iloc[0][col]
                    print(f"   {col}: '{value}' (type: {type(value)})")
                    if pd.notna(value) and str(value).strip() and str(value).strip().lower() != 'nan':
                        precautions.append(str(value).strip())
                
                print(f"✅ Extracted precautions: {precautions}")
                
            else:
                print(f"❌ No row found for '{test_disease}'")
        
    except Exception as e:
        print(f"❌ Error loading precautions: {e}")
        import traceback
        traceback.print_exc()
        
else:
    print(f"❌ Precaution file not found at: {PRECAUTION_PATH}")
    print(f"📁 Files in data directory:")
    data_dir = os.path.join(BASE_DIR, "data")
    if os.path.exists(data_dir):
        for file in os.listdir(data_dir):
            print(f"   - {file}")
    else:
        print(f"❌ Data directory doesn't exist: {data_dir}")

# Test the actual get_precautions function
print(f"\n🧪 TESTING get_precautions FUNCTION")
print("=" * 50)

try:
    import model_utils
    
    # Test with a known disease from your model
    print("🔍 Available diseases from model:")
    if hasattr(model_utils, 'clf'):
        diseases = model_utils.clf.classes_[:10]  # First 10
        for i, disease in enumerate(diseases, 1):
            print(f"  {i}. {disease}")
            
            # Test getting precautions
            precautions = model_utils.get_precautions(disease)
            print(f"     → Precautions: {len(precautions)} found")
            if precautions:
                print(f"     → First precaution: '{precautions[0]}'")
            print()
            
            if i >= 3:  # Test only first 3
                break
    
except Exception as e:
    print(f"❌ Error testing get_precautions: {e}")
    import traceback
    traceback.print_exc()