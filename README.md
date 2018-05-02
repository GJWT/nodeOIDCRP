OpenID Connect Relying Party
============================

## Introduction
Imagine that you have a web service where some of the functions that service provides are protected and should only be accessible to authenticated users or that some of the functions the service provides needs access to some user related resources on a resource server. That’s when you need OpenID Connect (OIDC) or Oauth2.

The RPHandler as implemented in oidcrp.RPHandler is a service within the web service that handles user authentication and access authorization on behalf of the web service.

## Some background
In the following description I will talk about Relying Party (RP) and OpenID Connect Provider (OP) but I could have talked about Oauth2 Client and OAuth2 Authorization Server instead. There are some differences in the details between the two sets but overall the entities work much the same way.

OAuth2 and thereby OpenID Connect (OIDC) are build on a request-response paradigm. The RP issues a request and the OP returns a response.

The OIDC core standard defines a set of such request-responses. This is a basic list of request-responses and the normal sequence in which they occur:

* Provider discovery (WebFinger)
* Provider Info Discovery
* Client registration
* Authorization/Authentication
* Access token
* User info

When a user accessing the web service for some reason needs to be authenticate or the service needs a access token that allows it to access some resources at a resource service on behalf of the user a number of things will happen:

* Find out which OP to talk to :
If the RP handler is configured to only communicate to a defined set of OPs then the user is probable presented a list to chose from. If the OP the user wants to authenticated at is unknown to the RP Handler it will use some discovery service to, given some information provided by the user, find out where to learn more about the OP.

* Gather information about the OP :
This can be done out-of-band in which case the administrator of the service has gathered the information by contacting the administrator of the OP. In most cases this is done by reading the necessary information on a web page provided by the organization responsible for the OP. One can also chose to gather the information on-the-fly by using the provider info discovery service provided by OIDC.

* Register the client with the OP :
Again this can be done beforehand or it can be done on-the-fly when needed. If it’s done before you will have to use a registration service provided by the organization responsible for the OP. If it’s to be done on-the-fly you will have to use the dynamic client registration service OIDC provides

* Authentication/Authorization :
This is done by the user at the OP.
What happens after this depends on which response_type is used. If the response_type is code then the following step is done:

* Access token request : 
Base on the information received in the authorization response a request for an access token is made to the OP
And if the web service wants user information it might also have to do:

* Obtain user info
Using the access token received above a userinfo request will be sent to the OP.




Which of the above listed services that your RP will use when talking to an OP are usually decided by the OP. Just to show you how it can differ between different OPs I’ll give you a couple of examples below:

* Google : 
If you want to use the Google OP as authentication service you should know that it is a true OIDC OP certified by the OpenID Foundation. You will have to manually register you RP at Google but getting Provider info can be done dynamically using an OIDC service. With Google you will use the response_type code. This means that you will need services 2,4,5 and 6 from the list above. More about how you will accomplish this below
* Microsoft :
Microsoft have chosen to only support response_type id_token and to return all the user information in the id_token. Microsoft’s OP supports dynamic Provider info discovery but client registration is done manual. What it comes down to is that you will only need services 2 and 4.
* Github : 
Now, to begin with Github is not running an OP they basically have an Oauth2 AS with some additions. It doesn’t support dynamic provider info discovery or client registration. If expects response_type to be code so services 4,5 and 6 are needed.


## Usage Examples
This method will initiate a RP/Client instance if none exists for the OP/AS in question. It will then run service 1 if needed, services 2 and 3 according to configuration and finally will asynchronously return a dictionary containing the URL that will redirect the user to the OP/AS and the session key which will allow higher level code to access session information. 

```
const BASEURL = 'https://example.com/rp';

const CLIENT_CONFIG = {...}

let rph = new RPHandler({baseUrl: BASEURL, clientConfigs: CLIENT_CONFIG});
let res = rph.begin(issuerId) 
let url = res[‘url’]
```

An http response is sent to the url which redirects to the OP/AS. The OP then sends back a redirect uri which contains the Authorization response with a set of claims. 

Usage example (params are the set of claims in the authorization response):
```
let sessionInfo = rph.sessionInterface.getState(res['state_key']);
```

Will parse the authorization response and depending on the configuration run the services 5 and 6.
Usage example:
```
 let client = rph.issuer2rp[session.claims['iss']];
 let authnMethod = rph.getClientAuthnMethod(client, 'token_endpoint');
 let authResponse = new AuthorizationResponse({code:'access_code', state: res['state_key']});
 let result = rph.finalizeAuth(client, session.claims['iss'], authResponse.claims);
```

RP configuration parameters
Disregarding if doing everything dynamically or statically you MUST define which services the RP/Client should be able to use.
* services
A specification of the usable services which possible changes to the default configuration of those service.
If you have done manual client registration you will have to fill in these:
* client_id
* The client identifier.
* client_secret
* redirect_uris

A set of URLs from which the RP can chose one to be added to the authorization request. The expectation is that the OP/AS will redirect the use back to this URL after the authorization/authentication has completed.
behavior

### Information about how the RP should behave towards the OP/AS
If the provider info discovery is done dynamically you need this
client_prefs

### How the RP should prefer to behave against the OP/AS
OP configuration parameters
* issuer
* The Issuer ID of the OP.
* allow
If there is a deviation from the standard as to how the OP/AS behaves this gives you the possibility to say you are OK with the deviation. Presently there is only one thing you can allow and that is the issuer in the provider info is not the same as the URL you used to fetch the information.
 
Example configuration of an RP Handler built using OICRP :  
```
"google": {
    "issuer": "https://accounts.google.com",
    "client_id": "4.apps.googleusercontent.com",
    "client_secret": "l17",
    "redirect_uris": ["{}/authz_cb/google".format(BASEURL)],
    "client_prefs": {
        "response_types": ["code"],
        "scope": ["openid", "profile", "email"],
        "token_endpoint_auth_method": ["client_secret_basic",
                                       'client_secret_post']
        },
    "services": [(’ProviderInfoDiscovery’, {}),
                 (’Authorization’, {}),
                 (’AccessToken’, {}), 
                 (’UserInfo’, {}]
},
"facebook": {
    "issuer": "https://www.facebook.com/v2.11/dialog/oauth",
    "client_id": "466",
    "client_secret": "db1",
    "behaviour": {
        "response_types": ["code"],
        "scope": ["email", "public_profile"],
        "token_endpoint_auth_method": ['']
    },
    "redirect_uris": ["{}/authz_cb/facebook".format(BASEURL)],
    "provider_info": {
        "authorization_endpoint":
            "https://www.facebook.com/v2.11/dialog/oauth",
        "token_endpoint":
            "https://graph.facebook.com/v2.11/oauth/access_token",
        "userinfo_endpoint":
            "https://graph.facebook.com/me"
        },
    'services': [(’oauth2.Authorization’, {}),
                 (’oauth2.AccessToken’, {'default_authn_method': ''}),
                 (’UserInfo’, {'default_authn_method': ''})]
},
'microsoft': {
    'issuer': 'https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0',
    'client_id': '24d',
    'client_secret': 'ipY',
    "redirect_uris": ["{}/authz_cb/microsoft".format(BASEURL)],
    "client_prefs": {
        "response_types": ["id_token"],
        "scope": ["openid"],
        "token_endpoint_auth_method": ["private_key_jwt",
                                       'client_secret_post'],
        "response_mode": 'form_post'
    },
    "allow": {"issuer_mismatch": True},
    "services": ['ProviderInfoDiscovery', 'Authorization']
}
```





