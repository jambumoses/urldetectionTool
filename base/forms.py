from django import forms

class URLForm(forms.Form):
    url = forms.URLField(label='', max_length=200, widget=forms.URLInput(attrs={'name':'url', 'class': 'input_url', 'placeholder': 'Enter your URL here'}))