import streamlit as st
import pickle
import string
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

ps = PorterStemmer()


def transform_text(text):
    text = text.lower()
    text = nltk.wordpunct_tokenize(text)

    y = []
    for i in text: # Only append alphabet and numerical excluding other letters
        if i.isalnum():
            y.append(i)

    text = y[:]
    y.clear()

    for i in text:
         if i not in stopwords.words('english') and i not in string.punctuation:
             y.append(i)

    text = y[:]
    y.clear()
    for i in text:
        y.append(   ps.stem(i))
    return " ".join(y)

tfidf = pickle.load(open('vectorizer.pkl', 'rb'))
model = pickle.load(open('model.pkl', 'rb'))

st.title('Email Classifier')
input_email = st.text_input('Enter Email text')


if st.button('Predict') and input_email.strip():
        # 1. Transform the text
        transform_email = transform_text(input_email)

        # 2. Vectorize the transformed text
        vectorized_email = tfidf.transform([transform_email])

        # 3. Predict the class
        prediction = model.predict(vectorized_email)[0]

        # Display the prediction
        if prediction == 1:
            st.header('Spam')
        else:
            st.header('Not Spam')

        # st.write('Predicted Class:', prediction[0])