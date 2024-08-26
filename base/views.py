from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from .forms import URLForm
from .models import AnalyzedURL
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
import joblib
import requests

# Load the trained SVM model
model = joblib.load('svm_model.pkl')
scaler = joblib.load('scaler.pkl')

# Create your views here.
def home(request):

    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            features = extract_features(url)
            features_scaled = scaler.transform([features])
            prediction = model.predict(features_scaled)[0]

            # Example API lookup
            api_result = check_url_with_api(url)

            # Save to the database
            analyzed_url = AnalyzedURL.objects.create(url=url, prediction=prediction, api_result=api_result)
            return render(request, 'pages/results.html', { 'url': url, 'prediction': prediction, 'api_result': api_result, 'page_title': "Fraud Detection",
        'page':'home'})
    else:
        form = URLForm()
    return render(request, 'pages/home.html', {'form': form, 'page_title': "Fraud Detection",'page':'home'})



def dashboard(request):

    return render(request, 'pages/dashboard.html',
    {
        #page needs
        'page_title': "Dashboard",
        'page':'Dashboard',
    }
    )

def results(request):

    return render(request, 'pages/results.html',
    {
        #page needs
        'page_title': "Fraud Detection",
        'page':'Results',
    }
    )


def report(request):

    return render(request, 'pages/report.html',
    {
        #page needs
        'page_title': "Fraud Detection Report",
        'page':'Report',
    }
    )

def docs(request):

    return render(request, 'pages/docs.html',
    {
        #page needs
        'page_title': "Fraud Detection Help Center",
        'page':'Docs',
    }
    )





""" functions """

def check_url_with_api(url):
    # Implement your API call logic here
    # Placeholder example
    return {"status": "safe"}

def extract_features(url):
    # Implement your feature extraction logic here
    # Placeholder example
    return [len(url), url.count('-'), url.count('.'), 1 if 'https' in url else 0]
