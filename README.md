# ZTNA
This Flask application with SQLAlchemy manages user authentication, role-based access, and real-time chat using Flask-SocketIO. It ensures thread safety for database operations and offers secure login with email OTP. The project demonstrates robust web development practices.
Additionally, the program includes functionalities for user registration, user removal, and user session management. The use of threading and locks ensures thread safety during database operations. The application also includes real-time chat functionality using Flask-SocketIO, enhancing its interactivity.
Overall, this project demonstrates a solid understanding of web development concepts, security practices, and database management, making it a commendable example of a well-implemented web application.
Steps to Start the Program:
1. Setup Database:
    Ensure you have SQLite installed.
    Run the db_setup.py script to create the database and populate it with initial data, including an admin user.

2.Start the Application:
    Run the app.py script to start the Flask application.
    The application will start running on http://localhost:5000.

3.Access the Application:
    Open a web browser and go to http://localhost:5000 to access the application.

4.Register an Admin User:
    Click on the "Register" link on the home page.
    Enter a username, password, and the admin secret key (12345 in this case).
    Select the resources the user should have access to.
    Click "Register" to create the admin user.

5.Login as Admin:
    Enter the admin username and password on the login page.
    If successful, you will be redirected to the admin dashboard, where you can manage users and resources.

6.Manage Users and Resources:
    From the admin dashboard, you can add new users, remove users, and view user details.
    You can also access resources based on your role and permissions.

7.Logout:
    Click on the "Logout" link to logout from the application.


Notes:
Ensure to adjust SMTP mail and all its components.
Ensure that the SECRET_KEY in app.py and the secret key used for admin registration match ('12345' in this case).
For security reasons, it is recommended to use a more secure secret key and password for admin registration in a production environment.
Admin user id = admin@example.com #change it before running the db_setup.db
Admin password = admin@1234
Admin secret key to add user = 12345
Ensure all the libraries are installed
