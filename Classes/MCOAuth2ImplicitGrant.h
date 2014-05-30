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
