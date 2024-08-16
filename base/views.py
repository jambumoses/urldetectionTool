from django.shortcuts import render

# Create your views here.
def home(request):

    return render(request, 'pages/home.html',
    {
        #page needs
        'page_title': "Fraud Detection",
        'page':'home',
    }
    )


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
