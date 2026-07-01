import os
import pickle
import logging

# Create a logger for this module to record informational, warning, and error messages.
logger = logging.getLogger(__name__)

#  Get the root directory of the Django project by moving up three folders from the current file.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Build the full path to the trained machine learning model file.
MODEL_PATH = os.path.join(PROJECT_ROOT, "ml_models", "model.pkl")

# Build the full path to the saved text vectorizer file.
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "ml_models", "vectorizer.pkl")

# print(PROJECT_ROOT)
# print(MODEL_PATH)
# print(VECTORIZER_PATH)

