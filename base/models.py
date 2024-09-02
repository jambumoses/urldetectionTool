from django.db import models

class ScannedUrls(models.Model):
   url = models.URLField(null=True, blank=True)
   api_result = models.JSONField(null=True, blank=True)
   url_id = models.CharField(max_length=500, null=True, blank=True)
   scan_id = models.CharField(max_length=500, null=True, blank=True)
   _type = models.CharField(max_length=200, null=True, blank=True)
   link_item = models.URLField(null=True, blank=True)
   link_self = models.URLField(null=True, blank=True)

   date = models.CharField(max_length=200, null=True, blank=True)
   malicious = models.IntegerField(null=True, blank=True) 
   suspicious = models.IntegerField(null=True, blank=True) 
   undetected = models.IntegerField(null=True, blank=True) 
   harmless = models.IntegerField(null=True, blank=True) 
   status = models.CharField(max_length=200, null=True, blank=True)
   timeout = models.IntegerField(null=True, blank=True) 

   method = models.CharField(max_length=200, null=True, blank=True)
   engine_name = models.CharField(max_length=200, null=True, blank=True)
   category = models.CharField(max_length=200, null=True, blank=True)
   result = models.CharField(max_length=200, null=True, blank=True) 
   created_at = models.DateTimeField(auto_now_add=True)
     
   def __str__(self):
       return self.url

# Create your models here.
#class AnalyzedURL(models.Model):
#    url = models.URLField()
#    prediction = models.BooleanField()
#    api_result = models.JSONField()
#    created_at = models.DateTimeField(auto_now_add=True)

#    def __str__(self):
#        return self.url
    
#.....................trained model.............................
# from sklearn.svm import SVC
# from sklearn.preprocessing import StandardScaler
# import joblib

# Sample data
#X = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]  # Replace with real features
#y = [0, 1, 0]  # Replace with real labels

# scaler = StandardScaler()
# X_scaled = scaler.fit_transform(X)

# model = SVC(kernel='linear', C=1)
# model.fit(X_scaled, y)

# # Save the model and scaler
# joblib.dump(model, 'svm_model.pkl')
# joblib.dump(scaler, 'scaler.pkl')
