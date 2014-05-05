//
//  MCOAuth2ThreeLegged.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2.h"


/**
 *  A class to handle authorization for confidential clients via the authorization code grant method.
 *
 *  This auth flow is designed for clients that are capable of protecting their client secret, which a distributed Mac/iOS App **is not**!
 */
@interface MCOAuth2AuthCodeGrant : MCOAuth2

/** The client id. */
@property (copy, nonatomic) NSString *clientId;

/** The client secret. */
@property (copy, nonatomic) NSString *clientSecret;

/** The redirect URL registered with the service provider. */
@property (copy, nonatomic) NSString *redirect;


/**
 *  The URL that should be used to authorize against, will be created from `authorizePath` and parameters passed during initialization IF AND ONLY IF those
 *  parameters are provided.
 */
@property (strong, nonatomic, readonly) NSURL *authorizeURL;

/** The URL path, relative to the base URL, to be used to request a token code. */
@property (copy, nonatomic, readonly) NSString *authorizePath;

/** The URL path, relative to the base URL, to be used to exchange a token code for an access token. */
@property (copy, nonatomic) NSString *tokenPath;

/** The code that can be traded for an access token. */
@property (copy, nonatomic) NSString *code;

/** The receiver's access token. */
@property (copy, nonatomic) NSString *accessToken;

/** A long-lived refresh token. */
@property (copy, nonatomic) NSString *refreshToken;


/**
 *  Designated initializer.
 *
 *  If you need a different API URL you can set it after initialization.
 *
 *  @param base The service's base URL, will be used to append OAuth and resource paths. E.g. @"https://www.service.com"
 *  @param authorize The path to the authorize URL when appended to `base`; don't forget the leading "/". E.g.: @"/oauth/authorize"
 *  @param token The path to the give-me-a-token URL when appended to `base`. E.g. @"/oauth/token"
 *  @param clientId Your client-id (or client-key)
 *  @param secret Your client secret
 *  @param redirect Your redirect URL
 *  @param scope The access scope you want to request
 */
- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
				token:(NSString *)token
			 clientId:(NSString *)clientId
			   secret:(NSString *)secret
			 redirect:(NSString *)redirect
				scope:(NSString *)scope;

/**
 *  Call this when you receive the redirect from your web view controller or browser, simply passing in the redirect URL returned by the server.
 *
 *  The callback will be used to determine whether a valid code was received and whether the token exchange happened successfully or not (if didCancel is NO
 *  and error is nil it means SUCCESS!!).
 *
 *  @param url The redirect URL returned by the server
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback;

/**
 *  If the code is received via other means than embedded in the redirect URL (e.g. for Google's services when using the "urn:ietf:wg:oauth:2.0:oob" redirect
 *  URL) you can use this method to receive the access token.
 *
 *  @note This method does not do state verification.
 
 *  @param code The code to exchange for an access token
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)exchangeCodeForToken:(NSString *)code callback:(void (^)(BOOL, NSError *))callback;


#pragma mark Resource Requests

/**
 *  Request a resource that returns JSON data.
 *
 *	If the returned data is nil and error is nil, the request has been aborted. Check for an error, if none occurred check for json data and handle the data,
 *  otherwise do nothing.
 *
 *  @param restPath The REST path, appended to the receiver's `baseURL`. Don't forget the leading "/", e.g. @"/api/v1/profile"
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)requestJSONResource:(NSString *)restPath callback:(void (^)(id jsonObject, NSError *error))callback;

@end
