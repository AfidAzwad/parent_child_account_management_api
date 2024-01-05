 Parent Child Account Management Rest Api Project Setup Guide


 Step 1: Clone the Project
   command:
    git clone <project_repository_url>
    cd <project_directory>

Step 2: Create a Virtual Environment
    command:
    python -m venv venv

    1. Activate the Virtual Environment
     command:
        On Windows:
        .\venv\Scripts\activate
        
        On Unix or MacOS:
        source venv/bin/activate

Step 3: Install Dependencies
 command:
    pip install -r requirements.txt

Step 4: Configure Database

  1. Edit the settings.py file to configure the database settings.

   command:
      python manage.py makemigrations
      python manage.py migrate

Step 5: Run Development Server
   command:
      python manage.py runserver
