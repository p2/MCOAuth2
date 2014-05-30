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

/** The client id. */
@property (copy, nonatomic) NSString *clientId;

/** Base API URL, all paths will be relative to this one. */
@property (strong, nonatomic) NSURL *apiURL;

/** The URL to authorize against. */
@property (strong, nonatomic) NSURL *authorizeURL;

/** The receiver's access token. */
@property (copy, nonatomic) NSString *accessToken;

/** Settings, as set upon initialization. */
@property (copy, nonatomic, readonly) NSDictionary *settings;

/** The redirect URL string currently in use. */
@property (copy, nonatomic, readonly) NSString *redirect;

/** The scope currently in use. */
@property (copy, nonatomic, readonly) NSString *scope;

/** The state sent to the server when requesting a token; we internally generate a UUID unless it's set manually. */
@property (copy, nonatomic) NSString *state;


/**
 *  Designated initializer, key support is experimental and currently informed by MITREid's reference implementation, with these additional
 *  keys:
 *    - authorize_uri
 *    - token_uri (for code grant)
 *    - scope
 *  MITREid: https://github.com/mitreid-connect/
 */
- (id)initWithSettings:(NSDictionary *)settings;


#pragma mark Authorization

/**
 *  Uses `authorizeURL` to construct the final authorize URL with the given parameters.
 *
 *  It is possible to use the `params` dictionary to override internally generated URL parameters, use it wisely.
 *
 *  @param redirect The redirect URI to supply. If it is nil, the first value of the settings' `redirect_uris` entries is used. Must be present in the end!
 *  @param scope The scope to request
 *  @param params Any additional parameters
 */
- (NSURL *)authorizeURLWithRedirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params;

/**
 *  Uses `authorizeURL` to construct the final authorize URL with the given parameters.
 *
 *  It is possible to use the `params` dictionary to override internally generated URL parameters, use it wisely.
 *
 *  @param url The base URL (with path, if needed) to build the URL upon
 *  @param redirect The redirect URI to supply. If it is nil, the first value of the settings' `redirect_uris` entries is used. Must be present in the end!
 *  @param scope The scope to request
 *  @param params Any additional parameters
 */
- (NSURL *)urlWithBase:(NSURL *)url redirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params;


#pragma mark Resource Requests

/**
 *  Request a resource that returns JSON data.
 *
 *	If the returned data is nil and error is nil, the request has been aborted. Check for an error, if none occurred check for json data and handle the data,
 *  otherwise do nothing.
 *
 *  @param restPath The REST path, appended to the receiver's `apiURL`. Don't forget the leading "/", e.g. @"/api/v1/profile"
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
