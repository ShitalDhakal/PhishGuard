import os
import pickle
import logging

# Create a logger for this module to record informational, warning, and error messages.
logger = logging.getLogger(__name__)

# Locate model files dynamically relative to Django project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(PROJECT_ROOT, "ml_models", "spam_model.pkl")
VECTORIZER_PATH = os.path.join(PROJECT_ROOT, "ml_models", "vectorizer.pkl")
