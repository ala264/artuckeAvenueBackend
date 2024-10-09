from django.shortcuts import render
from django.http import HttpResponse
from django.db import connection
from django.views.decorators.csrf import csrf_exempt
import json
import random
import string
import datetime
import jwt
import base64
from django.http import JsonResponse
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password

from django.shortcuts import render
from django.http import JsonResponse
from .forms import ImageUploadForm
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from .models import Article, Users, Draft_Article
from django.conf import settings

from django.core.mail import send_mail

#not refactored yet, and wont need to be refactored
@csrf_exempt
def insert_user(request):
    with connection.cursor() as cursor:
        # Define your SQL query with actual column names
        sql = "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)"
        # Define the values to insert
        values = ('Arman Lodhra', 'Armanlodhra@example.com', 'password123')
        # Execute the SQL query
        cursor.execute(sql, values)
    return HttpResponse("Data inserted successfully.")

#works 
@csrf_exempt
def insert_completed_article(request):
    #print(request)
    if request.method == 'POST':
        title = request.POST.get('title')
        contents = request.POST.get('contents')
        tag = request.POST.get('category')
        description = request.POST.get('description')
        username = request.POST.get('username')
        filename = request.POST.get('filename')
        # Getting the file
        thumbnail = request.FILES.get('thumbnail')

        # Create the article
        article = Article.objects.create(
            title=title,
            contents=contents,
            tag=tag,
            thumbnail=thumbnail,  
            description=description,
            username=username,
            filename=filename,
        )
        article.save()
        return JsonResponse({"message": "Article saved successfully"}, status=201)

#works 
@csrf_exempt
def get_completed_articles(request):
    try:
        articles = Article.objects.all().order_by('-created_at')
        result = []
        for article in articles:
            result.append({
                'id': article.id,
                'title': article.title,
                'contents': article.contents,
                'username': article.username,
                'filename': article.filename,
                'tag': article.tag,
                'description': article.description,
                'created_at': article.created_at,
                'thumbnail': article.thumbnail.url if article.thumbnail else None  # Add the thumbnail URL
            })
        
        return JsonResponse(result, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
    
@csrf_exempt
def get_articles_categories(request):
    try:
            # Get all articles and their associated usernames
        articles = Article.objects.all().order_by('-created_at')
        usernames = articles.values_list('username', flat=True).distinct()

        # Get user profile pictures based on the usernames in the articles
        users = Users.objects.filter(username__in=usernames).values('username', 'profile_pic')
        
        # Create a dictionary mapping usernames to their profile picture URLs
        users_data = {
            user['username']: f"{settings.MEDIA_URL}{user['profile_pic']}" if user['profile_pic'] else None
            for user in users
        }

        # Define categories
        categories = ['General', 'Sports', 'World-News', 'Science']
        categorized_articles = {category: [] for category in categories}

        # Categorize articles based on their tag
        for category in categories:
            category_articles = articles.filter(tag=category).order_by('-created_at')
            categorized_articles[category] = [
                {
                    'id': article.id,
                    'title': article.title,
                    'contents': article.contents,
                    'username': article.username,
                    'tag': article.tag,
                    'description': article.description,
                    'created_at': article.created_at,
                    'profile_pic': users_data.get(article.username),
                    'thumbnail': article.thumbnail.url if article.thumbnail else None
                }
                for article in category_articles
            ]

        # Prepare all articles data (without filtering by category)
        all_articles = [
            {
                'id': article.id,
                'title': article.title,
                'contents': article.contents,
                'username': article.username,
                'tag': article.tag,
                'description': article.description,
                'created_at': article.created_at,
                'profile_pic': users_data.get(article.username),
                'thumbnail': article.thumbnail.url if article.thumbnail else None
            }
            for article in articles
        ]

        # Prepare the final response with all articles and categorized articles
        response_data = {
            'all_articles': all_articles,
            'general': categorized_articles['General'],
            'sports': categorized_articles['Sports'],
            'worldnews': categorized_articles['World-News'],
            'science': categorized_articles['Science'],
        }

        return JsonResponse(response_data, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def get_completed_articles_categories(request):
    try:

        # Get completed articles with the specified tag (category)
        articles = Article.objects.filter(tag=category).order_by('-created_at')
        
        # Extract usernames from the articles
        usernames = articles.values_list('username', flat=True).distinct()
        
        # Get profile pics for those usernames
        users = Users.objects.filter(username__in=usernames).values('username', 'profile_pic')
        users_data = {user['username']: user['profile_pic'] for user in users}
        
        #categories = ['General', 'Sports', 'World-News', 'Science']
        #categorized_articles = {category: [] for category in categories}
        
        #for category in categories:
        #    cursor.execute(f"SELECT * FROM completed_articles WHERE tag = %s ORDER BY created_at DESC", [category])
        #    category_articles = cursor.fetchall()
        #    categorized_articles[category] = [dict(zip(columns, article)) for article in category_articles]

        # Prepare the response with all arrays
        #response_data = {
        #    'all_articles': results,
       #     'general': categorized_articles['General'],
        #    'sports': categorized_articles['Sports'],
        #    'worldnews': categorized_articles['World-News'],
        #    'science': categorized_articles['Science'],
        #}
        # Combine articles with profile pics
        result = []
        for article in articles:
            result.append({
                'id': article.id,
                'title': article.title,
                'contents': article.contents,
                'username': article.username,
                'tag': article.tag,  # This is 'tag' in the backend
                'description': article.description,
                'created_at': article.created_at,
            })
        
        return JsonResponse(result, safe=False)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

#works
@csrf_exempt
def insert_draft_article(request):
    try:
        # Use request.POST to get text fields and request.FILES to get file fields
        title = request.POST.get('title')
        contents = request.POST.get('contents')  # No need to use json.dumps
        description = request.POST.get('description')  # No need to use json.dumps
        username = request.POST.get('username')
        thumbnail = request.FILES.get('thumbnail')  # File field
        tag = request.POST.get('category')  # Category is sent as tag from frontend
        filename = request.POST.get('filename')

        # If no title is provided, generate one based on the count of existing draft articles
        draft_count = Draft_Article.objects.count()
        if not title or title.strip() == "":
            title = f"Article {draft_count + 1}"

        # Insert the draft article using Django ORM
        draft_article = Draft_Article.objects.create(
            contents=contents,
            title=title,
            username=username,
            thumbnail=thumbnail,  # Handle the file upload
            tag=tag,
            filename=filename,
            description=description
        )
        draft_article.save()

        return JsonResponse({"message": "Draft article inserted successfully."}, status=201)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

#works
@csrf_exempt
def get_draft_articles(request):
    try:
        # Fetch all draft articles, selecting only needed fields using values()
        draft_articles = Draft_Article.objects.values(
            'id', 'contents', 'title', 'username', 'thumbnail', 'tag', 
            'filename', 'description', 'created_at'
        ).order_by('-created_at')

        # If no draft articles are found
        if not draft_articles.exists():
            return JsonResponse([], safe=False, status=200)

        # Extract usernames from the draft articles
        usernames = draft_articles.values_list('username', flat=True).distinct()

        # Fetch user profile pics for those usernames
        users = Users.objects.filter(username__in=usernames).values('username', 'profile_pic')
        users_data = {user['username']: user['profile_pic'] for user in users}

        # Combine draft articles with user profile pics
        result = []
        for draft in draft_articles:
            result.append({
                'id': draft['id'],
                'contents': draft['contents'],
                'title': draft['title'],
                'username': draft['username'],
                'tag': draft['tag'],
                'description': draft['description'],
                'created_at': draft['created_at'],
                'filename': draft['filename'],
                'thumbnail': draft['thumbnail'],  # Assuming this is a file path
                'profile_pic': users_data.get(draft['username'])  # Add profile pic if available
            })

        return JsonResponse(result, safe=False, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def deleted_completed_article(request, article_id):
    try:
        # Try to find the article by its ID
        article = Article.objects.filter(id=article_id).first()

        # If the article is not found, return a 404 response
        if not article:
            return JsonResponse({"error": "Article not found or already deleted."}, status=404)

        # Delete the article
        article.delete()

        return JsonResponse({"message": f"Article {article_id} deleted successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def deleted_draft_article(request, article_id):
    try:
        # Try to find the draft article by its ID
        draft_article = Draft_Article.objects.filter(id=article_id).first()

        # If the draft article is not found, return a 404 response
        if not draft_article:
            return JsonResponse({"error": "Draft article not found or already deleted."}, status=404)

        # Delete the draft article
        draft_article.delete()

        return JsonResponse({"message": f"Draft article {article_id} deleted successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def update_draft_article(request, article_id):
    try:
        contents = request.POST.get('contents')
        description = request.POST.get('description')
        title = request.POST.get('title')
        thumbnail = request.FILES.get('thumbnail')
        tag = request.POST.get('category')
        filename = request.POST.get('filename')
        username = request.POST.get('username')
        

        # Try to find the draft article by its ID
        draft_article = Draft_Article.objects.filter(id=article_id).first()

        # If the draft article is not found, return a 404 response
        if not draft_article:
            return JsonResponse({"error": "Draft article not found or not updated."}, status=404)

        # Update the draft article with the new data
        draft_article.contents = contents
        draft_article.title = title
        draft_article.thumbnail = thumbnail
        draft_article.tag = tag
        draft_article.filename = filename
        draft_article.description = description

        # Save the changes
        draft_article.save()

        return JsonResponse({"message": f"Draft article {article_id} updated successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def update_completed_article(request, article_id):
    try:
        contents = request.POST.get('contents')
        description = request.POST.get('description')
        title = request.POST.get('title')
        thumbnail = request.FILES.get('thumbnail')
        tag = request.POST.get('category')
        filename = request.POST.get('filename')
        
        # Try to find the completed article by its ID
        article = Article.objects.filter(id=article_id).first()

        # If the article is not found, return a 404 response
        if not article:
            return JsonResponse({"error": "Completed article not found or not updated."}, status=404)

        # Update the article with the new data
        article.contents = contents
        article.title = title
        article.thumbnail = thumbnail
        article.tag = tag
        article.filename = filename
        article.description = description

        # Save the changes
        article.save()

        return JsonResponse({"message": f"Completed article {article_id} updated successfully."})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def get_article_by_username_and_name(request):
    # Extract the username and article name from the request's query parameters
    username = request.GET.get('username')
    title = request.GET.get('name')
    if not username or not title:
        return JsonResponse({'error': 'Username and article name are required'}, status=400)

    try:
        # Query to fetch the article by username and article title
        article = Article.objects.get(username=username, title=title)
        if article:
            # Query to fetch the author (user) by username
            author = Users.objects.get(username=username)
            if author:
                # Create the response data with article details and author's name
                article_data = {
                    'title': article.title,
                    'contents': article.contents,
                    'date': article.created_at,
                    'thumbnail': article.thumbnail.url if article.thumbnail else None,  # Adding image URL instead of object
                    'author': author.name,  # Adding the author's name
                }
                return JsonResponse(article_data, status=200)
            else:
                return JsonResponse({'error': 'Author not found'}, status=404)
        else:
            return JsonResponse({'error': 'Article not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e) + 'error bro'}, status=400)


# Output might be something like: 'A7dY5cVh9V2uKj1rLwZpXqA3T8aNsO6l'
#def generate_token(length=32):
 #   """Generate a random token."""
  #  return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

""""
@csrf_exempt
def sign_in(request):
  data = json.loads(request.body)
  email = data.get('email')
  password = data.get('password')
  with connection.cursor() as cursor:
    sql = "SELECT * FROM users WHERE email = %s"
    values = (email,)
    cursor.execute(sql, values)
    user = cursor.fetchone()
  
  #now we have a valid email
  if user:
    # check to see if the password is valid
    stored_password = user[4]  # Assuming 'password' is the first column
    if check_password(password, stored_password):
        print('user found ')
        #using jwt: 
        payload = {
           'id': email,
           'exp': datetime.datetime.now() + datetime.timedelta(minutes=60),
           'iat': datetime.datetime.now()
        }

        token = jwt.encode(payload, 'secret', algorithm='HS256')
        response = JsonResponse({'message': 'user found', 'token': token})
        response.set_cookie(
           key='jwt',
           value=token, 
           httponly=True ,  
           max_age=3600, 
           path='/', 
           samesite='None', 
           secure=False)
       
        return response
    else:
        print('password incorrect')
        return JsonResponse({'message': 'password incorrect'}, safe=False)  
  else:
    print('username not found')
    return JsonResponse({'message': 'user not found'}, safe=False)
*/

def test(request):
    print(request.session.get('user_email'))
    return JsonResponse({'message': 'Session data set'})
"""
@csrf_exempt
def check_session(request):
    # Check if the session has the key 'user_id' or any custom key you're using
    user_email = request.session.get('user_email')
    
    if user_email:
        # Session is valid, user is logged in
        return JsonResponse({'status': 'valid', 'user_email': user_email})
    else:
        # Session is invalid, user is not logged in
        return JsonResponse({'status': 'invalid'}, status=401)    


@csrf_exempt
def sign_in(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')
        password = data.get('password')
        #print(email)
        # Fetch the user by email using Django ORM
        user = Users.objects.filter(email=email).first()
        #print(f"User fetched: {user}")  # Debugging information
        if user:
            # Check if the password is valid
            if check_password(password, user.password):
                # Set session data
                request.session['user_email'] = email
                request.session['username'] = user.username
                request.session['name'] = user.name
                print("User found")
                return JsonResponse({'message': 'User found'}, status=200)
            else:
                print("Password incorrect")
                return JsonResponse({'message': 'Password incorrect'}, status=401)
        else:
            print("User not found")
            return JsonResponse({'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@csrf_exempt
def getSessionData(request):
  if(request.session.get('user_email')):
    return JsonResponse({
      'name': request.session.get('name'),
      'email': request.session.get('user_email'),
      'username': request.session.get('username'),
    })
  return JsonResponse('error', 'no session data')

@csrf_exempt
def getAuthorInfo(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            if not username:
                return JsonResponse({'error': 'Username not provided'}, status=400)

            # Fetch the user by username using Django ORM
            author = Users.objects.filter(username=username).first()

            if author:
                # Return the author info as a dictionary
                author_info = {
                    'id': author.id,
                    'name': author.name,
                    'email': author.email,
                    'username': author.username,
                    'profile_pic': author.profile_pic.url if author.profile_pic else None,
                    'author_desc': author.author_desc,
                }
                print('author_info')
                return JsonResponse({'authorInfo': author_info}, status=200)
            else:
                return JsonResponse({'error': 'User not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def insertProfilePic(request):
   data = json.loads(request.body)
   profilePic = data.get('profilePic')
   with connection.cursor() as cursor:
    sql = "UPDATE users SET profile_pic = %s WHERE username = 'ala264'" # change the profile username
    cursor.execute(sql, (profilePic,))
    author = cursor.fetchone()

""""
@csrf_exempt
def get_author_info(request):
    # Get the username from the request (assuming it's a POST request with JSON data)
    if request.method == 'POST':
        import json
        body = json.loads(request.body)
        username = body.get('username', None)  

        if not username:
            return JsonResponse({'error': 'Username is required'}, status=400)

        try:
            # Prepare the SQL query using the provided username
            with connection.cursor() as cursor:
                cursor.execute(""
                    SELECT id, created_at, contents, title, username, thumbnail
                    FROM completed_articles
                    WHERE username = %s
                    ORDER BY created_at DESC
                "", [username])

                # Fetch all rows from the executed query
                rows = cursor.fetchall()

                # Map the results to a dictionary format
                articles = []
                for row in rows:
                    articles.append({
                        'id': row[0],
                        'created_at': row[1],
                        'contents': row[2],
                        'title': row[3],
                        'username': row[4],
                        'thumbnail': row[5]
                    })

                # Return the JSON response with the articles
                return JsonResponse(articles, safe=False)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)
"""

@csrf_exempt
def get_articles_by_username(request):
    # Filter articles based on username and title
    body = json.loads(request.body)
    username = body.get('username', None)      
    articles = Article.objects.filter(username=username)
    # Check if there are any matching articles
    if articles.exists():
        # Prepare a list of articles to return
        response_data = []
        for article in articles:
            article_data = {
                'id': article.id,
                'username': article.username,
                'title': article.title,
                'contents': article.contents,
                'thumbnail': article.thumbnail.url,  # File path for the thumbnail
                'tag': article.tag,
                'description': article.description,
                'created_at': article.created_at,
                'filename': article.filename,
            }
            #print(article_data)
            response_data.append(article_data)

        # Return the list of articles as JSON
        return JsonResponse(response_data, safe=False, status=200)
    
    else:
        return JsonResponse({'error': 'No articles found'}, status=404)
    
@csrf_exempt
def get_drafts_by_username(request):
        # Filter articles based on username and title
    body = json.loads(request.body)
    username = body.get('username', None)      
    articles = Draft_Article.objects.filter(username=username)

    # Check if there are any matching articles
    if articles.exists():
        # Prepare a list of articles to return
        response_data = []
        for article in articles:
            article_data = {
                'id': article.id,
                'username': article.username,
                'title': article.title,
                'contents': article.contents,
                'thumbnail': article.thumbnail.url,  # File path for the thumbnail
                'tag': article.tag,
                'description': article.description,
                'created_at': article.created_at,
                'filename': article.filename,
            }
            #print(article_data)
            response_data.append(article_data)

        # Return the list of articles as JSON
        return JsonResponse(response_data, safe=False, status=200)
    
    else:
        return JsonResponse({'error': 'No articles found'}, status=404)


@csrf_exempt
def signup_view(request):
    if request.method == 'POST':
        try:
            name = request.POST.get('name')
            email = request.POST.get('email')
            password = request.POST.get('password')  # Plain text password from form
            username = request.POST.get('username')
            author_desc = request.POST.get('author_desc')
            profile_pic = request.FILES.get('profile_pic')
            filename = request.POST.get('filename')

            # Hash the password before saving it
            hashed_password = make_password(password)

            # Create a new user
            user = Users(
                name=name,
                email=email,
                password=hashed_password,  # Store the hashed password
                username=username,
                author_desc=author_desc,
            )

            # If there's a profile picture, save it
            if profile_pic:
                user.profile_pic = profile_pic
                user.filename = filename

            user.save()

            return JsonResponse({"message": "User signed up successfully."}, status=201)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method."}, status=405)

@csrf_exempt
def submit_author_response(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            response = data.get('response')

            # Compose the email
            subject = 'New Author Application'
            message = f'Why should you become an author?\n\n{response}'
            from_email = 'armanlodhra29@gmail.com'
            recipient_list = ['armanlodhra@icloud.com', 'hussain.capitals@gmail.com']

            # Send the email
            send_mail(subject, message, from_email, recipient_list)

            return JsonResponse({'message': 'Response submitted and email sent successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'message': 'Failed to send the email', 'error': str(e)}, status=400)
    return JsonResponse({'message': 'Invalid request method'}, status=405)
