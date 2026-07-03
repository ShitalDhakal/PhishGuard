import os
import re
import pickle
import logging
import string

import nltk
# Data Processing
# Natural Language Processing (NLP) that transforms raw text into a clean and structured format suitable for machine learning.
# Since SMS messages often contain unnecessary words, punctuation, special characters, and inconsistent formatting, preprocessing helps improve the
# quality of the data and enhances the performance of the spam classification model.


# A corpus is simply a collection of data. In this case, it's a collection of common words.
from nltk.corpus import stopwords
# Stop words are commonly used words that carry little meaningful information and are often removed during text preprocessing.

# Import PorterStemmer to reduce words to their root form (e.g., "running" → "run").
from nltk.stem.porter import PorterStemmer

# Create a logger for this module to record informational, warning, and error messages.
logger = logging.getLogger(__name__)
# Eg : [analyzer.services.ml_classifier] ERROR: Error loading ML model files.

#  Get the root directory of the Django project by moving up three folders from the current file.
ML_MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ml_models")

# Build the full path to the trained machine learning model file.
MODEL_PATH = os.path.join(ML_MODELS_DIR, "model.pkl")

# Build the full path to the saved text vectorizer file.
VECTORIZER_PATH = os.path.join(ML_MODELS_DIR, "vectorizer.pkl")

# print(PROJECT_ROOT)
# print(MODEL_PATH)
# print(VECTORIZER_PATH)

# Placeholder for the loaded machine learning model.
_model = None

# Placeholder for the loaded text vectorizer.
_vectorizer = None

# PorterStemmer instance — reused across calls (stateless, safe to share).
_ps = PorterStemmer()

def strip_keywords_line(text):
    """
    Removes the artificial 'Keywords: ...' line injected into synthetic phishing
    training emails in phishing_legit_dataset_KD_10000.csv.

    Applied defensively at inference time so that any email containing a literal
    'Keywords:' line (e.g. a tech digest) is not unfairly biased toward phishing.

    Example:
        Input : 'Your account is locked.\n\nKeywords: pin password ssn\n\nRegards'
        Output: 'Your account is locked.\n\nRegards'
    """
    return re.sub(r'Keywords:.*', '', text, flags=re.IGNORECASE).strip()


def transform_text(text):
    """
    Preprocesses raw email text to match the exact cleaning pipeline used
    during model training in ml_classifier_phishing.md.
    Steps:
        1. Convert text to lowercase.
           Example: "LOCKED Account" → "locked account"
        2. Tokenize into individual words.
           Example: "verify your identity now!" → ["verify", "your", "identity", "now", "!"]
        3. Keep only alphanumeric tokens.
           Example: ["verify", "your", "identity", "now", "!"] → ["verify", "your", "identity", "now"]
        4. Remove common English stop words and punctuation.
           Example: ["this", "is", "a", "secure", "link"] → ["secure", "link"]
        5. Apply Porter Stemming to reduce words to their root form.
           Example: ["verifying", "suspended", "clicked"] → ["verifi", "suspend", "click"]
    """
    # Step 1: Lowercase
    text = text.lower()


    # Step 2: Tokenize
    text = nltk.wordpunct_tokenize(text)

    # Step 3: Keep only alphanumeric tokens
    y = []
    for i in text:
        if i.isalnum():
            y.append(i)

    text = y[:]
    y.clear()

    # Step 4: Remove stop words and punctuation
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(i)

    text = y[:]
    y.clear()

    # Step 5: Apply stemming
    for i in text:
        y.append(_ps.stem(i))

    return " ".join(y)
    # " ".join(y) joins every word using a space.
'''Eg: [
         'secur',
         'link',
         'click',
         'verifi',
         'account'
 ] to this form: "secur link click verifi account"'''

def load_models():
    """
       Loads model and vectorizer from the ml_models directory.
       Returns True if successful, False otherwise.
    """


    global _model, _vectorizer # # Access the global model and vectorizer variables so they can be loaded once and reused.

    # checks whether the model (model.pkl) and vectorizer (vectorizer.pkl) have already been loaded into memory.
    if _model is not None and _vectorizer is not None:
        return True  # This improves performance because the model is loaded only once.

    # Check whether both the model and vectorizer files exist.
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        logger.warning(
            f"ML Model files not found at {MODEL_PATH} or {VECTORIZER_PATH}. "
            "Please run 'python ml_models/train_spam_model.py' to generate them."
        )
        return False # returns False to indicate that the model and vectorizer could not be loaded.

    try:
        with open(MODEL_PATH, "rb") as f:
            # Loads (deserializes) the trained machine learning model from model.pkl into the _model variable.
            _model = pickle.load(f)
        with open(VECTORIZER_PATH, "rb") as f:
            _vectorizer = pickle.load(f)
        return True
    except Exception as e:
        logger.error(f"Error loading ML model files: {e}")
        return False


def classify(email_body):
    """
    Calculates the probability that the email body is phishing.

    Input: email_body (string)
    Returns: ml_score (int: 0 to 100) representing phishing probability
    """

    # 1. Check for missing body

    if not email_body or not email_body.strip():
        # Return 0 if the email body is empty or contains only whitespace.
        return 0

    # 2. This part first execute load_models() function, if the above function return False, only execute and return 0
    if not load_models():
        '''
        classify() first calls load_models(). If load_models() returns False (meaning the model or vectorizer could 
        not be loaded), then classify() immediately returns 0. If load_models() returns True,
        the function continues with email classification.
        '''
        # Safe fallback if models aren't trained yet
        return 0

    try:
        # 3. Strip any 'Keywords: ...' lines (defensive — matches training preprocessing)
        #    then preprocess: lowercase → tokenize → remove stopwords → stem
        #    Without this step, words like "locked" won't match the trained token "lock".
        cleaned_text = transform_text(strip_keywords_line(email_body))

        # 4. Vectorize the cleaned text using the trained TF-IDF vectorizer
        #    Converts the cleaned string into a 3000-dimensional numerical vector.
        vectorized_text = _vectorizer.transform([cleaned_text])

        # 5. Predict probability
        # classes_ order is [0=legitimate, 1=phishing]
        probabilities = _model.predict_proba(vectorized_text)[0]
        classes = _model.classes_

        # Find the index of the phishing class (encoded as 1)
        phishing_index = list(classes).index(1)
        phishing_probability = probabilities[phishing_index]

        # 6. Convert the phishing probability (0.0–1.0) into a percentage score (0–100).
        ml_score = int(round(phishing_probability * 100))

        # Return the final machine learning spam score.
        return ml_score
    except Exception as e:
        logger.error(f"Error executing ML classification: {e}")
        return 0


if __name__ == "__main__":
    test_mail = [
        # -- Legitimate emails (expected: score <= 50) --
        (
            "Legitimate",
            """Subject: Project Planning Meeting Next Week

            Hi team, 
            
            I would like to schedule a quick Zoom meeting to go over the project timeline next week. Please check your calendar and let me know if Monday afternoon works for you, or suggest an alternative time. I will send a calendar invite once we confirm.
            
            Warm regards,
            Sarah
            """
        ),
        (
            "Phishing",
            """Dear People's Bank Client,

            Your profile has been locked because of too many failed login attempts.
            Unlock your profile using your ATM/Visa Check Card number and PIN,
            or your Social Security Number and Account number.

            People's Bank Account Review Department."""
        ),
        (
            "Phishing",
            """CONGRATULATIONS! Your email was selected as the GRAND PRIZE WINNER
            of our International Online Promotional Lottery worth $606,009.
            Claim your prize immediately to avoid forfeiture. Act now."""
        ),
        # -- Legitimate emails (expected: score < 50) --
        (
            "Legitimate",
            """Subject: Project update review

            Hi team, thanks for the review. Please verify your tasks before the meeting tomorrow.

            Best, Sam"""
        ),
        (
            "Legitimate",
            """Subject: Appointment reminder

            This is a reminder that you have an appointment on May 08, 2026 at 10:45 AM.
            To reschedule or cancel, please use the link below.

            Appointment Desk"""
        ),
        (
            "Legitimate",
            """Subject: Newsletter subscription confirmation

            Congratulations, you are subscribed! Click here to update your profile settings.

            Regards, Alex"""
        ),
    ]

    print("=== ML Classifier Test ===")
    correct = 0
    for expected, _mail in test_mail:
        score = classify(_mail)
        label = "Phishing" if score >= 50 else "Legitimate"
        match = "✓" if label == expected else "✗"
        correct += 1 if label == expected else 0
        print(f"{match} [{label:9s}] Score={score:3d}   {_mail[:60].strip()}")
    print(f"\nResult: {correct}/{len(test_mail)} correct")
