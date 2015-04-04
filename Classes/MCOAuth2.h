//
//  MCOAuth2.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

@import Foundation;
@class MCOAuth2;


/**
 *  OAuth2 delegate protocol
 */
@protocol MCOAuth2Delegate <NSObject>

@optional
- (void)oauth2:(MCOAuth2 *)oauth2 didAuthorizeWithParameters:(NSDictionary *)params;

@end


/**
 *  An abstract superclass for our simple OAuth2 client.
 */
@interface MCOAuth2 : NSObject

/** An optional delegate. */
@property (weak, nonatomic) id<MCOAuth2Delegate> delegate;

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

/** Set to YES to log all the things. NO by default. */
@property (nonatomic) BOOL verbose;


/**
 *  Designated initializer, key support is experimental and currently informed by MITREid's reference implementation, with these additional
 *  keys:
 *    - client_id
 *    - client_secret (for code grant)
 *    - api_uri
 *    - authorize_uri
 *    - token_uri (for code grant)
 *    - scope
 *    - verbose (applies to client logging, unrelated to the actual OAuth exchange)
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
- (NSURL *)authorizeURLWithBase:(NSURL *)url redirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params;

/**
 *  Called with all parameters that are returned in a valid (!) response carrying the access token.
 *
 *  Subclasses should call super at one point to ensure that the delegate receives the callback.
 */
- (void)didAuthorizeWithParameters:(NSDictionary *)params;


#pragma mark Resource Requests

/**
 *  Requests a resource, optionally with a specific type.
 *
 *	If the returned data is nil and error is nil, the request has been aborted. Check for an error, if none occurred check for data and handle the data,
 *  otherwise do nothing.
 *
 *  @param restPath The REST path, appended to the receiver's `apiURL`
 *  @param accept Optional; the mime type to request in an "Accept:" header
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)requestResource:(NSString *)restPath accept:(NSString *)accept callback:(void (^)(NSData *data, NSError *error))callback;

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

/** Debug logging, will only log if `verbose` is YES. */
- (void)logIfVerbose:(NSString *)log, ...;

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
