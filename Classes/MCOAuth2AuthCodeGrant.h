//
//  MCOAuth2CodeGrant.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2.h"


/**
 *  A class to handle authorization for confidential clients via the authorization code grant method.
 *
 *  This auth flow is designed for clients that are capable of protecting their client secret, which a distributed
 *  Mac/iOS App **is not**!
 */
@interface MCOAuth2AuthCodeGrant : MCOAuth2

/** The client secret. */
@property (copy, nonatomic) NSString *clientSecret;

/** The URL to be used to exchange a token code for an access token. */
@property (strong, nonatomic) NSURL *tokenURL;

/** A long-lived refresh token. */
@property (copy, nonatomic) NSString *refreshToken;


/**
 *  Call this when you receive the redirect from your web view controller or browser, simply passing in the redirect URL
 *  returned by the server.
 *
 *  The callback will be used to determine whether a valid code was received and whether the token exchange happened
 *  successfully or not (if didCancel is NO and error is nil it means SUCCESS!!). The instance's `code` property will
 *  be properly filled.
 *
 *  @param url The redirect URL returned by the server
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback;

/**
 *  If the code is received via other means than embedded in the redirect URL (e.g. for Google's services when using the
 *  "urn:ietf:wg:oauth:2.0:oob" redirect URL) you can use this method to receive the access token.
 *
 *  @note This method does not do state verification.
 *
 *  @param code The code to exchange for an access token
 *  @param callback A callback that will have `didCancel` = NO and `error` = nil on success
 */
- (void)exchangeCodeForToken:(NSString *)code callback:(void (^)(BOOL didCancel, NSError *error))callback;

/**
 *  Attempts to get a new access token with a refresh token.
 */
- (void)refreshTokenWithCallback:(void (^)(BOOL didCancel, NSError *error))callback;

@end
