//
//  MCOAuth2.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

@import Foundation;


/**
 *  An abstract superclass for our simple OAuth2 client.
 */
@interface MCOAuth2 : NSObject

/** The base URL, all paths will be relative to this one. */
@property (strong, nonatomic) NSURL *baseURL;

/** Optional base API URL, in case the authentication host is different from the API host (e.g. a subdomain). Defaults to `baseURL`. */
@property (strong, nonatomic) NSURL *apiURL;

/** The receiver's access token. */
@property (copy, nonatomic) NSString *accessToken;

/** Initializer, uses the designated initializer with a `nil` apiURL parameter. */
- (id)initWithBaseURL:(NSURL *)base;

/** Designated initializer. */
- (id)initWithBaseURL:(NSURL *)base apiURL:(NSURL *)api;


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


#pragma mark Utilities

/** Return a new UUID. */
+ (NSString *)newUUID;

/** Create a query string from a dictionary. */
+ (NSString *)queryStringFor:(NSDictionary *)params;

/** Parse a query string into a dictionary. */
+ (NSDictionary *)paramsFromQuery:(NSString *)query;

/**
 *  Handles access token error response.
 *  @param params The URL parameters passed into the redirect URL upon error
 *  @return An NSError instance with the "best" localized error key and all parameters in the userInfo dictionary; domain "MCOAuth2ErrorDomain", code 600
 */
+ (NSError *)errorForAccessTokenErrorResponse:(NSDictionary *)params;

@end


#ifndef MC_ERR
# define MC_ERR(mc_err_p, mc_err_s, mc_err_c) if (mc_err_p != NULL && mc_err_s) {\
		*mc_err_p = [NSError errorWithDomain:NSCocoaErrorDomain code:(mc_err_c ? mc_err_c : 0) userInfo:@{NSLocalizedDescriptionKey: mc_err_s}];\
	}\
	else {\
		NSLog(@"%s (line %d) ignored error: %@", __PRETTY_FUNCTION__, __LINE__, mc_err_s);\
	}
#endif
