from django.db import models

# Create your models here.
# article_app/models.py

from django.db import models

class Article(models.Model):
    id = models.AutoField(primary_key=True)
    contents = models.TextField()
    title = models.TextField()
    username = models.TextField()
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True)
    tag = models.TextField(blank=True, null=True)  # Optional field for tags
    description = models.TextField(blank=True, null=True)  # Optional field for article description
    filename = models.TextField(blank=True, null=True)  # Optional field to store the original file name
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'completed_articles'  

class Draft_Article(models.Model):
    id = models.AutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    contents = models.TextField()
    title = models.TextField()
    username = models.TextField()
    thumbnail = models.ImageField(upload_to='thumbnails/', blank=True, null=True)
    tag = models.TextField(blank=True, null=True)  # Optional field for tags
    description = models.TextField(blank=True, null=True)  # Optional field for article description
    filename = models.TextField(blank=True, null=True)  # Optional field to store the original file name

    class Meta:
        db_table = 'draft_articles'  

class Users(models.Model):
    id = models.AutoField(primary_key=True)
    created_at = models.DateTimeField(auto_now_add=True)
    name = models.TextField()
    email = models.TextField()
    password = models.TextField()
    username = models.TextField()
    author_desc = models.TextField()
    profile_pic = models.ImageField(upload_to='profile_pic/', blank=True, null=True)
    filename = models.TextField(blank=True, null=True)  # Optional field to store the original file name

    class Meta:
        db_table = 'users'  
