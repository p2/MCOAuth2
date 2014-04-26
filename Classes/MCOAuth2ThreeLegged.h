//
//  MCOAuth2ThreeLegged.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2.h"


/**
 *  A class to handle three-legged OAuth2 authorization and resource fetching.
 */
@interface MCOAuth2ThreeLegged : MCOAuth2

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
@property (copy, nonatomic) NSString *authorizePath;

/** The URL path, relative to the base URL, to be used to exchange a token code for an access token. */
@property (copy, nonatomic) NSString *tokenPath;

/** The code that can be traded for an access token. */
@property (copy, nonatomic) NSString *code;

/** The receiver's access token. */
@property (copy, nonatomic) NSString *accessToken;

/** A long-lived refresh token. */
@property (copy, nonatomic) NSString *refreshToken;


/** Designated initializer. */
- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
				token:(NSString *)token
			 clientId:(NSString *)clientId
			   secret:(NSString *)secret
			 redirect:(NSString *)redirect
				scope:(NSString *)scope;

/**
 *  Call this when you receive the callback from your web view controller, simply passing in the redirect URL.
 *  The callback will be used to determine whether a valid code was received and whether the token exchange happened successfully or not (if didCancel is NO
 *  and error is nil it means SUCCESS!!).
 */
- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback;

#pragma mark Resource Requests

/**
 *  Request a resource that returns JSON data.
 *	If the returned data is nil and error is nil, the request has been aborted. Check for an error, if none occurred check for json data and handle the data,
 *  otherwise do nothing.
 */
- (void)requestJSONResource:(NSString *)restPath callback:(void (^)(id jsonObject, NSError *error))callback;

@end
