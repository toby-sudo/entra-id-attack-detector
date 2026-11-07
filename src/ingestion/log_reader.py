
import pandas as pd
from pathlib import Path


def load_signin_logs(file_path):
    """
    Load Entra ID-style sign-in logs from a CSV file.
    """

    try:
        logs = pd.read_csv(file_path)

        print("Sign-in logs loaded successfully.")
        print(f"Total events: {len(logs)}")

        return logs

    except FileNotFoundError:
        print("Error: Log file not found.")
        return None

    except pd.errors.EmptyDataError:
        print("Error: The CSV file is empty.")
        return None


if __name__ == "__main__":

    project_root = Path(__file__).resolve().parents[2]

    file_path = project_root / "data" / "raw" / "signin_logs.csv"

    logs = load_signin_logs(file_path)

    if logs is not None:
        print("\nFirst five sign-in events:")
        print(logs.head())
