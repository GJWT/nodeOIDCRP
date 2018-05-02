/**
 * @fileoverview Node JS Library for Message protocols
 *
 * @description 
 * <pre>
 * OpenID Connect Relying Party
 * <pre>
 * Introduction<pre>
 * Imaging that you have a web service where some of the functions that service provides are 
 * protected and should only be accessible to authenticated users or that some of the functions 
 * the service provides needs access to some user related resources on a resource server. That’s
 * when you need OpenID Connect (OIDC) or Oauth2.
 * <pre>
 * The RPHandler as implemented in RPHandler is a service within the web service that
 * handles user authentication and access authorization on behalf of the web service.
 * <pre>
 * Some background<pre>
 * In the following description I will talk about Relying Party (RP) and OpenID Connect Provider 
 * (OP)but I could have talked about Oauth2 Client and OAuth2 Authorization Server instead. There 
 * are some differences in the details between the two sets but overall the entities work much the
 * same way.
 * <pre>
 * OAuth2 and thereby OpenID Connect (OIDC) are build on a request-response paradigm. The RP issues 
 * a request and the OP returns a response.
 * <pre>
 * The OIDC core standard defines a set of such request-responses. This is a basic list of 
 * request-responses and the normal sequence in which they occur:<pre>
 * Provider discovery (WebFinger) <pre>
 * Provider Info Discovery<pre>
 * Client registration <pre>
 * Authorization/Authentication <pre>
 * Access token <pre>
 * User info <pre>
 * <pre>
 * When a user accessing the web service for some reason needs to be authenticate or the service 
 * needs a access token that allows it to access some resources at a resource service on behalf of
 * the user a number of things will happen:
 * <pre>
 * Find out which OP to talk to :<pre>
 * If the RP handler is configured to only communicate to a defined set of OPs then the user is 
 * probably presented a list to chose from. If the OP the user wants to authenticated at is unknown 
 * to the RP Handler it will use some discovery service to, given some information provided by the 
 * user, find out where to learn more about the OP.<pre>
 * <pre>
 * Gather information about the OP :<pre>
 * This can be done out-of-band in which case the administrator of the service has gathered the 
 * information by contacting the administrator of the OP. In most cases this is done by reading the
 * necessary information on a web page provided by the organization responsible for the OP. One can
 * also chose to gather the information on-the-fly by using the provider info discovery service 
 * provided by OIDC.<pre>
 * <pre>
 * Register the client with the OP :<pre>
 * Again this can be done beforehand or it can be done on-the-fly when needed. If it’s done before 
 * you will have to use a registration service provided by the organization responsible for the OP.
 * If it’s to be done on-the-fly you will have to use the dynamic client registration service OIDC 
 * provides.<pre>
 * <pre>
 * Authentication/Authorization :<pre>
 * This is done by the user at the OP.
 * <pre>
 * What happens after this depends on which response_type is used. If the response_type is code then 
 * the following step is done:
 * <pre>
 * Access token request : 
 * Base on the information received in the authorization response a request for an access token is
 * made to the OP. 
 * <pre>
 * And if the web service wants user information it might also have to do:
 * <pre>
 * Obtain user info
 * Using the access token received above a userinfo request will be sent to the OP.
 * <pre>
 * Which of the above listed services that your RP will use when talking to an OP are usually 
 * decided by the OP. Just to show you how it can differ between different OPs I’ll give you a 
 * couple of examples below:
 * <pre>
 * Google : <pre>
 * If you want to use the Google OP as authentication service you should know that it is a true OIDC
 * OP certified by the OpenID Foundation. You will have to manually register you RP at Google but 
 * getting Provider info can be done dynamically using an OIDC service. With Google you will use the
 * response_type code. This means that you will need services 2,4,5 and 6 from the list above. More 
 * about how you will accomplish this below
 * <pre>
 * Microsoft :<pre>
 * Microsoft have chosen to only support response_type id_token and to return all the user 
 * information in the id_token. Microsoft’s OP supports dynamic Provider info discovery but client 
 * registration is done manual. What it comes down to is that you will only need services 2 and 4.
 * <pre>
 * Github : <pre>
 * Now, to begin with Github is not running an OP they basically have an Oauth2 AS with some 
 * additions. It doesn’t support dynamic provider info discovery or client registration. If expects 
 * response_type to be code so services 4,5 and 6 are needed.
 * <pre>
 */