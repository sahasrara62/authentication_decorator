# Authentication Decorators in Flask
#### Implement an auth decorator to validate the permission of the provided user in the JWT token


An API designed in flask. Implement an auth decorator to validate the permission of the provided user in the JWT token.

Tasks:
1.	Create a new Python Flask-RESTful project or modify your existing project.
2.	Implement the JWT authentication and token generation endpoints as described in the previous task.
3.	Implement the auth decorator function that checks the permission level of the user in the JWT token.
4.	The auth decorator should take a permission level as a parameter and return a function that can be used as a decorator for Flask-RESTful endpoints.
5.	The decorator function should check the user's permission level in the JWT token and allow access to the endpoint if the user has the required permission level. If the user does not have the required permission level, the decorator should return an HTTP 403 Forbidden error.
6.	Add appropriate error handling to your API. You should handle errors like invalid tokens or missing permission levels in the JWT token.
7.	Create endpoints for CRUD operations on user data. These endpoints should be restricted based on the user's permission level:

	- a new user: Requires admin permission.
	- Retrieve a user's details: Requires either admin permission or the user themselves.
	- Update a user's details: Requires either admin permission or the user themselves.
	- Delete a user: Requires admin permission.

## Setup
1. Create directory and `cd` into the directory
2. clone the repo `git clone https://github.com/sahasrara62/authentication_decorator.git` 
3. python used 3.9.16
3. setup a virtualenv `python -m venv venv`
4. activate virtualenv `source venv/bin/activate`
4. install dependencies `python -m pip install -r requirements.txt`

## Running the application
> activate virtualenv: `source venv/bin/activate`
> 
> type: `export FLASK_APP=app.py`
> run command `flask run`
> serving on: `https://127.0.0.1:5000/`


## Endpoints
- Use postman or curl to test the endpoints
- Parse auth token in `x-access-token` header.
1. User register: POST `/signup`
2. User login: POST `/login`
3. Get user details: GET `/users/details/<username>`
4. Delete a user: Delete `/users/delete/<username>'`
5. Update user details: PUT `/users/update/<username>/<name>`


## Details

This Repo is built to do task Implement an auth decorator to validate the permission of the provided user in the JWT token. 

### Techstack
 - *Programming language*: python 3.9.16
 - *web framework*: flask
 - *database* : sqlite

 
## information
   
  * by default dababase api.db is used
  * admin profile is added inside db, with details as 
  >username = admin, password=admin, permission=admin
  
  
## Setup database from sctratch
1. remove existing migration if present
2. define database uri in `config.py` file
3. run commands 
   ```
   python -m flask db init
   python -m flask db migrate
   python -m flask db upgrade
   ```
4. add Admin in the db, go to flask shell `python -m flask shell`         , then run following code
   ```
   from library.models import User
   from library.main import db
   
   # defining admin user
   admin_user = User(username='admin', password='password', admin=True, permissions='admin')
   
   # saving user details in db
   db.session.add(admin_user)
   db.session.commit()
   ```

### API token handling logic

User hit endpoint `/login`  with credentials 'username' and 'password', will get a token, use that token to the headers of other request, header field value is `x-access-token`, this token include user information and the permission, based on that user can access the enpoint and do CURD 

# Endpoint details

1. `/login`
   - method: POST
   - body : {"username": "admin", "password": "password"}
   - endpont example: ```http://127.0.0.1:5000/login```
   - response: *sucessful* -> `{"token": "token_string"}`
               *erorr* -> could not verify user

2. `/users/details/<username>`
   - method: GET
   - params: None
   - headers = {'x-access-token': <token_got_on_login>}
   
   add username in the url end point and will get the result

3. `/users/signup`

   - method: POST
   - request body : {'username':'username', 'password':'password', 'permission': 'user'}
   - headers:          {'x-access-token': <token_got_on_login>}
   
   a login admin can sign up the user 
 
4. `/users/delete/<username>`
   
   - method: DELETE
   - headers:          {'x-access-token': <token_got_on_login>}
 
   An admin can delete user have username present in db
 
5. `/users/update/<username>/<name>`
   - method: PUT
   - headers:          {'x-access-token': <token_got_on_login>}

   login user can update his deltails
