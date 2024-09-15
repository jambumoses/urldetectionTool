from django.shortcuts import render, redirect
from .models import ScannedUrls
import json

# Create your views here.
from django.shortcuts import render, redirect
from .forms import URLForm
#from .models import AnalyzedURL
#from sklearn.svm import SVC
#from sklearn.preprocessing import StandardScaler
#import joblib
import time
import requests
from .models import ScannedUrls

#all reports
allreports = ScannedUrls.objects.all().order_by('-id').values()


# Load the trained SVM model
#model = joblib.load('svm_model.pkl')
#scaler = joblib.load('scaler.pkl')

# API Keys
VIRUSTOTAL_API_KEY = '5b7a2ee262a1786aea2a18243fd40c4bbd7e62cc6dbef8dece8381ebf19d5c32'
GOOGLE_SAFE_BROWSING_API_KEY = 'AIzaSyDUWGLTF42vj28CC55NfO5DRABRIicQrKs'


# Create your views here.
def home(request):

    if request.method == 'POST':
        form = URLForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            vt_result, gs_result, overall_safe = check_url(url)
        
            #vt_result = json.dump(vt_result)
            #risk_dist = (100 - 63)
            risk_dist = (100 - vt_result['data']['attributes']['stats']['harmless'])
            
            #populate database
            reportInput = ScannedUrls(
                url = vt_result['meta']['url_info']['url'],
                api_result = vt_result['data'],
                url_id = vt_result['meta']['url_info']['id'],
                scan_id = vt_result['data']['id'],
                _type = vt_result['data']['type'],
                link_item = vt_result['data']['links']['item'],
                link_self = vt_result['data']['links']['self'],
                date = vt_result['data']['attributes']['date'],
                malicious = vt_result['data']['attributes']['stats']['malicious'],
                suspicious = vt_result['data']['attributes']['stats']['suspicious'],
                undetected = vt_result['data']['attributes']['stats']['undetected'],
                harmless = vt_result['data']['attributes']['stats']['harmless'],
                status = vt_result['data']['attributes']['status'],
                timeout = vt_result['data']['attributes']['stats']['timeout'],
                method = vt_result['data']['attributes']['results']['Acronis']['method'],
                engine_name = vt_result['data']['attributes']['results']['Acronis']['engine_name'],
                category = vt_result['data']['attributes']['results']['Acronis']['category'],
                result = vt_result['data']['attributes']['results']['Acronis']['result']
            )
            reportInput.save()


            #clean data
            # cleaned_result = dict()

            # for scan in vt_result:
            #     if scan['data']['attributes']['stats']['malicious'] < 10 and scan['data']['attributes']['stats']['suspicious'] < 10 and scan['data']['attributes']['stats']['harmless'] > 50:
            #         scan['data']['attributes']['results']['Acronis']['category'] = 'Harmless'
            #     elif scan['data']['attributes']['stats']['malicious'] < 30 or scan['data']['attributes']['stats']['suspicious'] > 50 and scan['data']['attributes']['stats']['harmless'] < 50:
            #         scan['data']['attributes']['results']['Acronis']['category'] = 'Suspicious'
            #     elif scan['data']['attributes']['stats']['malicious'] > 30 or scan['data']['attributes']['stats']['suspicious'] > 30 and scan['data']['attributes']['stats']['harmless'] < 50:
            #         scan['data']['attributes']['results']['Acronis']['category'] = 'Malicious'
            #     scan['data']['attributes']['stats']
                
            #     cleaned_result = scan
                
            
            #features = extract_features(url)
            #features_scaled = scaler.transform([features])
            #prediction = model.predict(features_scaled)[0]

            # Example API lookup
            #api_result = check_url_with_api(url)

            # Save to the database
            #analyzed_url = AnalyzedURL.objects.create(url=url, prediction=prediction, api_result=api_result)
            return render(request, 'pages/results.html', {'url': url,'risk': risk_dist, 'safety': overall_safe, 'prediction': "prediction", 'api_result': vt_result,'google_safety': gs_result, 'page_title': "Fraud Detection",'page':'home'})
    else:
        form = URLForm()
    return render(request, 'pages/home.html', {'form': form, 'page_title': "Fraud Detection",'page':'home'})



def dashboard(request):
    
    # legitemate = ""
    # warning = ""
    # dangerous = ""
    # undetected = ""
    
    # if (report.malicious < 10) and (report.suspicious < 10) and (report.harmless > 50):
    #     legitemate = "Legitemate"
    # elif (report.malicious < 30) or (report.suspicious > 50) and (report.harmless < 50):
    #     warning = "Warning"
    # elif (report.malicious > 30) or (report.suspicious > 30) and (report.harmless < 50):
    #     dangerous = "Dangerous"
    # else:
    #     undetected = "Undetected"
    #suspiciousCount = ScannedUrls.objects.filter(category="suspicious").values().count()
    maliciousCount = 0 #ScannedUrls.objects.filter(category="malicious").values().count()
    suspiciousCount = 0
    harmlessCount = 0 #ScannedUrls.objects.filter(category="harmless").values().count()
    
    cleaned_reports = list()

    for report in allreports:
        
        if report['malicious'] < 10 and report['suspicious'] < 10 and report['harmless'] > 50:
            report['category'] = 'Harmless'
            harmlessCount = harmlessCount + 1
        elif report['malicious'] < 30 or report['suspicious'] > 50 and report['harmless'] < 50:
            report['category'] = 'Suspicious'
            suspiciousCount = suspiciousCount + 1
        elif report['malicious'] > 30 or report['suspicious'] > 30 and report['harmless'] < 50:
            report['category'] = 'Malicious'
            maliciousCount = maliciousCount + 1
        
        cleaned_reports.append(report)
        #if report.malicious < 30 or allreports.suspicious > 50 and allreports.harmless < 50:
        #    suspiciousCount = 1

    
    
    
    return render(request, 'pages/dashboard.html',
    {
        #page needs
        'page_title': "Dashboard",
        'page':'Dashboard',
        'allreports': cleaned_reports,
        'suspiciousCount':suspiciousCount,
        'maliciousCount': maliciousCount,
        'harmlessCount': harmlessCount 
    }
    )

def results(request):

    # return render(request, 'pages/results.html',
    # {
    #     #page needs
    #     'page_title': "Fraud Detection",
    #     'page':'Results',
    # }
    # )
    return redirect('home')
    
def singleResult(request,id):
    
    singleReport = {}
    risk_dist = 0
    
    cleaned_reports = list()

    for report in allreports:
        
        if report['malicious'] < 10 and report['suspicious'] < 10 and report['harmless'] > 50:
            report['category'] = 'Harmless'
        elif report['malicious'] < 30 or report['suspicious'] > 50 and report['harmless'] < 50:
            report['category'] = 'Suspicious'
        elif report['malicious'] > 30 or report['suspicious'] > 30 and report['harmless'] < 50:
            report['category'] = 'Malicious'
        
        cleaned_reports.append(report)

    
    
    for report in cleaned_reports:
        if report['id'] == id:
            singleReport = report
            
            risk_dist = (100 - report['harmless'])


    
    return render(request,'pages/singleResult.html',{
        'id':id ,
        'risk': risk_dist,
        'page_title': "Fraud Detection",
        #'page':'Scan on '+singleReport['url'],
        'api_result': singleReport,
    })


def report(request):
    
    maliciousCount = 0
    suspiciousCount = 0
    harmlessCount = 0 
    
    cleaned_reports = list()

    for report in allreports:
        
        if report['malicious'] < 10 and report['suspicious'] < 10 and report['harmless'] > 50:
            report['category'] = 'Harmless'
            harmlessCount = harmlessCount + 1
        elif report['malicious'] < 30 or report['suspicious'] > 50 and report['harmless'] < 50:
            report['category'] = 'Suspicious'
            suspiciousCount = suspiciousCount + 1
        elif report['malicious'] > 30 or report['suspicious'] > 30 and report['harmless'] < 50:
            report['category'] = 'Malicious'
            maliciousCount = maliciousCount + 1
        
        cleaned_reports.append(report)

    return render(request, 'pages/report.html',
    {
        #page needs
        'page_title': "Fraud Detection Report",
        'page':'Report',
        'allreports': cleaned_reports,#ScannedUrls.objects.all(),
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





# functions

# def check_url_with_api(url):
#     # Implement your API call logic here
#     # Placeholder example
#     return {"status": "safe"}

# def extract_features(url):
#     # Implement your feature extraction logic here
#     # Placeholder example
#     return [len(url), url.count('-'), url.count('.'), 1 if 'https' in url else 0]


def search(request):
    
    search_string = request.GET.get('search','default')
    maliciousCount = 0
    suspiciousCount = 0
    harmlessCount = 0 
    
    cleaned_reports = list()
    #ScannedUrls.objects.all().filter(url__icontains=search_string).order_by('-id').values()
    for report in ScannedUrls.objects.filter(url__icontains=search_string).order_by('-id').values():
        
        if report['malicious'] < 10 and report['suspicious'] < 10 and report['harmless'] > 50:
            report['category'] = 'Harmless'
            harmlessCount = harmlessCount + 1
        elif report['malicious'] < 30 or report['suspicious'] > 50 and report['harmless'] < 50:
            report['category'] = 'Suspicious'
            suspiciousCount = suspiciousCount + 1
        elif report['malicious'] > 30 or report['suspicious'] > 30 and report['harmless'] < 50:
            report['category'] = 'Malicious'
            maliciousCount = maliciousCount + 1
        
        cleaned_reports.append(report)
    
    return render(request, 'pages/report.html',
    {
        #page needs
        'page_title': "Fraud Detection Help Center",
        'page':'Search',
        'allreports': cleaned_reports,
    }
    )
 
 
 
def check_url(url):
    # VirusTotal URL submission
    vt_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    data = {'url': url}
    vt_response = requests.post(vt_url, headers=headers, data=data)
    vt_result = vt_response.json()

    # Extract analysis ID for detailed results
    analysis_id = vt_result.get('data', {}).get('id')
    if not analysis_id:
        return None, None, False  # Return early if the analysis ID is missing

    # Wait for analysis to complete and fetch results
    vt_analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    time.sleep(15)
    vt_analysis_response = requests.get(vt_analysis_url, headers=headers)
    vt_analysis_result = vt_analysis_response.json()

    # Determine VirusTotal safety status
    vt_safe = True
    if 'data' in vt_analysis_result and 'attributes' in vt_analysis_result['data']:
        last_analysis_results = vt_analysis_result['data']['attributes'].get('last_analysis_results', {})
        for scan in last_analysis_results.values():
            if scan.get('category') == 'malicious':
                vt_safe = False
                break

    # Google Safe Browsing check
    gs_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
    payload = {
        'client': {
            'clientId': 'yourcompanyname',
            'clientVersion': '1.5.2'
        },
        'threatInfo': {
            'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [{'url': url}]
        }
    }
    gs_response = requests.post(gs_url, json=payload)
    gs_result = gs_response.json()

    # Determine Google Safe Browsing safety status
    gs_safe = not bool(gs_result.get('matches'))

    # Overall safety determination
    overall_safe = vt_safe and gs_safe

    return vt_analysis_result, gs_result, overall_safe