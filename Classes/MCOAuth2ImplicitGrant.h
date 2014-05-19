//
//  MCOAuth2ImplicitGrant.h
//  MCOAuth2App
//
//  Created by Pascal Pfiffner on 5/5/14.
//  Copyright (c) 2014 Pascal Pfiffner. All rights reserved.
//

#import "MCOAuth2.h"


/**
 *  Class to handle OAuth2 requests for public clients, such as distributed Mac/iOS Apps.
 */
@interface MCOAuth2ImplicitGrant : MCOAuth2

/** The client id. */
@property (copy, nonatomic) NSString *clientId;

/** The redirect URL registered with the service provider. */
@property (copy, nonatomic) NSString *redirect;


/**
 *  The URL that should be used to authorize against.
 *
 *  It will be created from `authorizePath` and parameters passed during initialization IF AND ONLY IF those parameters are provided.
 */
@property (strong, nonatomic, readonly) NSURL *authorizeURL;

/** The URL path, relative to the base URL, to be used to request a token. */
@property (copy, nonatomic, readonly) NSString *authorizePath;


/**
 *  Designated initializer.
 *
 *  If you need a different API URL you can set `apiURL` after initialization.
 *
 *  @param base The service's base URL, will be used to append OAuth and resource paths. E.g. @"https://www.service.com"
 *  @param authorize The path to the authorize URL when appended to `base`. E.g.: @"/oauth/authorize"
 *  @param clientId Your client-id (or client-key)
 *  @param redirect Your redirect URL
 *  @param scope The access scope you want to request
 */
- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
			 clientId:(NSString *)clientId
			 redirect:(NSString *)redirect
				scope:(NSString *)scope;

/**
 *  Call this when you receive the redirect from your web view controller or browser, simply passing in the redirect URL returned by the server.
 *
 *  The callback will be used to determine whether a valid token was received or not (if didCancel is NO and error is nil it means SUCCESS!!).
 *
 *  @param url The redirect URL returned by the server
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)handleRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback;

@end
