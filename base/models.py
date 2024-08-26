from django.db import models

# Create your models here.
class AnalyzedURL(models.Model):
    url = models.URLField()
    prediction = models.BooleanField()
    api_result = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url
    
#.....................trained model.............................
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
import joblib

# Sample data
X = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]  # Replace with real features
y = [0, 1, 0]  # Replace with real labels

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

model = SVC(kernel='linear', C=1)
model.fit(X_scaled, y)

# Save the model and scaler
joblib.dump(model, 'svm_model.pkl')
joblib.dump(scaler, 'scaler.pkl')
