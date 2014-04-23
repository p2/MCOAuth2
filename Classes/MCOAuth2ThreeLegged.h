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

/** The URL that should be used to authorize against. */
@property (strong, nonatomic, readonly) NSURL *authorizeURL;

/** Designated initializer. */
- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
			 exchange:(NSString *)exchange
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
