# Auth Service
The auth service is designed to handle `auth_request` directives from the nginx server. 

## 
- [ ] Create HTTP Server
    - [x] Basic Hello World listener
    - [ ] Setup routes 
        - [ ] `/auth/google/callback`
        - [ ] `/auth/login`
    - [ ] Create middlewares
        - [x] Request logger
        - [ ] Check cookie data
            - [ ] If cookie exists
                * Parse cookie data as user struct
                * Check cookie data against fresh DB data
                * Sign a new cookie if needed
                * Pass user struct to next middleware
            - [ ] If cookie doesn't exist, should redirect to a login page
        - [ ] Check user permissions
            - [ ] If user is permitted, returns 200
            - [ ] Otherwise returns 401
        - [ ] Login Handler
            - [ ] If user exists, creates a cookie for them and redirect to the original route requested
            - [ ] If user doesn't exist, log user in DB awaiting approval from Admin
- [ ] Create pg_db package
    - [x] Initialize database connection
    - [x] Get user data from tables
    - [ ] Create new users
    - [ ] Get route authentication rules

## Auth Service Decision Tree
The logic the auth service uses to authenticate users. 
 
* Auth service receives an `auth_request` from nginx
* Checks for existence of auth cookie and checks integrity
    * If the token is valid...
        * and the user has permission for the route, returns 200.
        * but the user doesn't have permission, returns 401.
    * If the token doesn't exist or is invalid...
        * The user is redirected to a login page
            * If the user credentials are valid... 
                * new token is created as a cookie
                * The user is redirected to the original route and their cookie checked as normal
            * If the user credentials are invalid...
                * they are redirected to an error page or create account page