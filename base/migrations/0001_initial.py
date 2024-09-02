# Generated by Django 5.0.1 on 2024-08-27 10:32

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ScannedUrls',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.URLField(blank=True, null=True)),
                ('api_result', models.JSONField(blank=True, null=True)),
                ('_id', models.TextField(blank=True, null=True)),
                ('scan_id', models.TextField(blank=True, null=True)),
                ('_type', models.CharField(blank=True, max_length=200, null=True)),
                ('link_item', models.URLField(blank=True, null=True)),
                ('link_self', models.URLField(blank=True, null=True)),
                ('date', models.DateTimeField(blank=True, null=True)),
                ('malicious', models.IntegerField(blank=True, null=True)),
                ('suspicious', models.IntegerField(blank=True, null=True)),
                ('undetected', models.IntegerField(blank=True, null=True)),
                ('harmless', models.IntegerField(blank=True, null=True)),
                ('status', models.CharField(blank=True, max_length=200, null=True)),
                ('timeout', models.IntegerField(blank=True, null=True)),
                ('method', models.CharField(blank=True, max_length=200, null=True)),
                ('engine_name', models.CharField(blank=True, max_length=200, null=True)),
                ('category', models.CharField(blank=True, max_length=200, null=True)),
                ('result', models.CharField(blank=True, max_length=200, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
        ),
    ]
