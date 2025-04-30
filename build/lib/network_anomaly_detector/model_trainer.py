import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import joblib
import os
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler


def load_and_preprocess_data(file_path):
    """
    Load and preprocess the dataset.
    """
    # Load the dataset
    data = pd.read_csv(file_path)
    data.columns = data.columns.str.strip()

    # Debug: Check for missing values before handling
    print("[DEBUG] Missing values per column before handling:\n",
          data.isnull().sum())

    # Fill missing values with 0 or the mean of each column
    data = data.fillna(0)  # Replace NaN with 0
    data = data.replace([np.inf, -np.inf], 0)  # Replace inf/-inf with 0

    # Debug: Check for missing values after handling
    if data.isnull().values.any():
        print("[ERROR] Missing values still exist after preprocessing!")
    else:
        print("[INFO] No missing values detected.")

    # Extract features and labels
    X = data.drop(columns=["Label"])
    y = data["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

    # Normalize the features
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    return X, y


def train_model(X, y):
    """
    Train the XGBoost model and evaluate it.
    """
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42)

    # Train the XGBoost model
    model = XGBClassifier(
        n_estimators=100,            # Number of trees
        learning_rate=0.1,           # Learning rate
        max_depth=6,                 # Maximum depth of trees
        scale_pos_weight=len(y) / sum(y),  # Handle class imbalance
        random_state=42
    )
    model.fit(X_train, y_train)

    # Make predictions on the test set
    y_pred = model.predict(X_test)

    # Print evaluation report
    print("[INFO] Evaluation Report:\n")
    print(classification_report(
        y_test, y_pred, target_names=["BENIGN", "MALICIOUS"]))

    # Save the model
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/xgboost_model.pkl")
    print("[INFO] Model saved to models/xgboost_model.pkl")


def main():
    # Path to the dataset
    # Replace with the actual path to your dataset
    file_path = "/Users/salman/Documents/Learning/UWindsor/COMP4680/combined_file.csv"

    # Load and preprocess the data
    X, y = load_and_preprocess_data(file_path)

    # Train the model
    train_model(X, y)


if __name__ == "__main__":
    main()
