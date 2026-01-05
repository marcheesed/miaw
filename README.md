### :cat2: miaw.cc 

a lightweight, easy to use python pastebin website.

in production, miaw.cc comes in at only 500kb average, with a fast and efficient backend, as little code as possible, and a simple and intuitive frontend based on the nostalgic themes of the early indie web.
our main app.py is just over 1k lines of code for the backend.

## features

- [x] user registration and login, changing of usernames, passwords, pfp uploads and handling
- [x] create and view pastes
- [x] admin / user management
- [x] search bar for pastes
- [x] ip logging
- [x] password protected pastes
- [x] csrf protection, html/css sanitization
- [x] invite codes


## installation

please read the requirements.txt file for dependencies

make sure you are not running other webservers on a 5001 port, or change the port in the app.py file

```
pip install -r requirements.txt
```
you need to initialize the database by running the following command
```
python3 app.py
```
then you'll need to do this to add a temporary admin user into the database and badges for staff, contributor, a warning role and beta testers. edit these if you please.
```
python3 init.py
```
once inserted, run the app again to start the server locally on a 5001 port
```
python3 app.py
```

# contributors

- [mellowcoffee](https://github.com/mellowcoffee)
