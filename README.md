 Parent Child Account Management Rest Api Project Setup Guide


 Step 1: Clone the Project
 
       git clone <project_repository_url>
       cd <project_directory>

Step 2: Create a Virtual Environment

     python -m venv venv

    1. Activate the Virtual Environment

        On Windows:
        .\venv\Scripts\activate
        
        On Unix or MacOS:
        source venv/bin/activate

Step 3: Install Dependencies

        pip install -r requirements.txt

Step 4: Configure Database

  1. Edit the settings.py file to configure the database settings.
     
         python manage.py makemigrations
       
         python manage.py migrate

Step 5: Run Development Server

       python manage.py runserver
