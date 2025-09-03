# Auth Service
The auth service is designed to handle `auth_request` directives from the nginx server. 

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