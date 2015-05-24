//
//  MCOAuth2CodeGrant.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2AuthCodeGrant.h"


@interface MCOAuth2AuthCodeGrant ()

/** The code that can be traded for an access token. */
@property (copy, nonatomic) NSString *code;

@end


@implementation MCOAuth2AuthCodeGrant


- (id)initWithSettings:(NSDictionary *)settings
{
	if ((self = [super initWithSettings:settings])) {
		self.clientSecret = settings[@"client_secret"];
		if ([settings[@"token_uri"] length] > 0) {
			self.tokenURL = [NSURL URLWithString:settings[@"token_uri"]];
		}
		self.clientKeySecretInBody = [settings[@"secret_in_body"] boolValue] || !_clientSecret;
	}
	return self;
}



#pragma mark - OAuth Dance

- (NSURL *)authorizeURLWithRedirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params
{
	NSMutableDictionary *mute = ([params count] > 0) ? [params mutableCopy] : [NSMutableDictionary dictionaryWithCapacity:1];
	mute[@"response_type"] = @"code";
	[mute addEntriesFromDictionary:params];
	
	return [self authorizeURLWithBase:self.authorizeURL redirect:redirect scope:scope additionalParameters:[mute copy]];
}

- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL, NSError *))callback
{
	NSError *error = nil;
	if (![self validateRedirectURL:url error:&error]) {
		if (callback) {
			callback(NO, error);
		}
		return;
	}
	
	[self exchangeCodeForToken:_code callback:callback];
}

- (void)exchangeCodeForToken:(NSString *)code callback:(void (^)(BOOL didCancel, NSError *error))callback
{
	// do we have a code, client secret and an exchange URL?
	NSError *error = nil;
	if (!_code) {
		MC_ERR(&error, @"I don't have a code to exchange, let the user authorize first", 0);
	}
	else if (!self.clientId) {
		MC_ERR(&error, @"I do not yet have a client id, cannot exchange code for a token", 0);
	}
	else if (!_clientSecret) {
		MC_ERR(&error, @"I do not yet have a client secret, cannot exchange code for a token", 0);
	}
	else if (!_tokenURL) {
		MC_ERR(&error, @"I'm missing `tokenURL`, please configure me correctly", 0);
	}
	
	if (error) {
		[self logIfVerbose:@"Trying to exchange code for acces token, but", error.localizedDescription, nil];
		if (callback) {
			callback(NO, error);
		}
		return;
	}
	
	[self logIfVerbose:@"Exchanging code for access token:", code, nil];
	self.code = code;
	
	// construct request dictionary and execute it
	NSDictionary *params = @{
		@"client_id": self.clientId,
		@"redirect_uri": self.redirect,
		@"grant_type": @"authorization_code",
		@"code": self.code
	};
	if (_clientKeySecretInBody) {
		NSMutableDictionary *mute = [params mutableCopy];
		mute[@"client_secret"] = self.clientSecret;
		params = mute;
	}
	
	[self performAccessTokenRequestWithParams:params callback:callback];
}

- (void)didAuthorizeWithParameters:(NSDictionary *)params
{
	self.accessToken = params[@"access_token"];
	self.refreshToken = params[@"refresh_token"];
	[self logIfVerbose:@"Successfully extracted access token", nil];
	
	[super didAuthorizeWithParameters:params];
}



#pragma mark - Refresh Token

- (void)refreshTokenWithCallback:(void (^)(BOOL didCancel, NSError *error))callback
{
	NSError *error = nil;
	if (0 == [_refreshToken length]) {
		MC_ERR(&error, @"I do not have a refresh token", 0);
	}
	else if (!self.clientId) {
		MC_ERR(&error, @"I do not yet have a client id, cannot refresh token", 0);
	}
	else if (!_clientSecret) {
		MC_ERR(&error, @"I do not yet have a client secret, cannot refresh token", 0);
	}
	else if (!_tokenURL) {
		MC_ERR(&error, @"I'm missing `tokenURL`, please configure me correctly", 0);
	}
	
	if (error) {
		[self logIfVerbose:@"Trying to refresh token, but", error.localizedDescription, nil];
		if (callback) {
			callback(NO, error);
		}
		return;
	}
	
	[self logIfVerbose:@"Refreshing token", nil];
	
	// construct request dictionary and execute it
	NSDictionary *params = @{
		@"grant_type": @"refresh_token",
		@"refresh_token": self.refreshToken,
	};
	if (_clientKeySecretInBody) {
		NSMutableDictionary *mute = [params mutableCopy];
		mute[@"client_id"] = self.clientId;
		mute[@"client_secret"] = self.clientSecret;
		params = mute;
	}
	
	[self performAccessTokenRequestWithParams:params callback:callback];
}



#pragma mark - Utilities

/**
 *  Creates a POST request, form-urlencoding the given params into the request's body and sending it off using NSURLSession.
 */
- (void)performAccessTokenRequestWithParams:(NSDictionary *)params callback:(void (^)(BOOL didCancel, NSError *error))callback
{
	NSMutableURLRequest *post = [[NSMutableURLRequest alloc] initWithURL:self.tokenURL];
	[post setHTTPMethod:@"POST"];
	[post setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
	[post setHTTPBody:[[[self class] queryStringFor:params] dataUsingEncoding:NSUTF8StringEncoding]];
	
	if (!_clientKeySecretInBody) {
		NSData *userpass = [[NSString stringWithFormat:@"%@:%@", self.clientId, self.clientSecret ?: @""] dataUsingEncoding:NSUTF8StringEncoding];
		NSString *basic = [NSString stringWithFormat:@"Basic %@", [userpass base64EncodedStringWithOptions:0]];
		[post setValue:basic forHTTPHeaderField:@"Authorization"];
	}
	
#if 0
	NSLog(@"[MCOAuth2] REQUEST %@:  %@", post.HTTPMethod, post.URL);
	NSLog(@"[MCOAuth2] REQUEST HEAD:  %@", [post allHTTPHeaderFields]);
	NSLog(@"[MCOAuth2] REQUEST BODY:  %@", [[NSString alloc] initWithData:post.HTTPBody encoding:NSUTF8StringEncoding]);
#endif
	
	NSURLSession *session = [NSURLSession sharedSession];
	NSURLSessionTask *task = [session dataTaskWithRequest:post completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
		NSError *myError = error ?: [self parseAccessTokenResponse:response withData:data];
		if (callback) {
			callback(NO, myError);
		}
	}];
	[task resume];
}

/**
 *  Parse responses from code exchange and token refresh.
 *
 *  @returns An error if something breaks, nil otherwise
 */
- (NSError *)parseAccessTokenResponse:(NSURLResponse *)response withData:(NSData *)data
{
	NSError *error = nil;
	NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
	if ([http isKindOfClass:[NSHTTPURLResponse class]]) {
		if (http.statusCode < 400) {
			NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
			if ([json isKindOfClass:[NSDictionary class]]) {
				
				// got a token
				if ([json[@"access_token"] length] > 0) {
					[self didAuthorizeWithParameters:json];
				}
				else {
					error = [[self class] errorForAccessTokenErrorResponse:json];
				}
			}
			else {
				NSString *err_msg = [NSString stringWithFormat:@"Expected a JSON encoded dictionary, but got: %@", json];
				MC_ERR(&error, err_msg, 0);
			}
		}
		else {
			MC_ERR(&error, [NSHTTPURLResponse localizedStringForStatusCode:http.statusCode], http.statusCode)
		}
	}
	else {
		MC_ERR(&error, @"No HTTP-type response", 0)
	}
	return error;
}

- (BOOL)validateRedirectURL:(NSURL *)url error:(NSError **)error
{
	[self logIfVerbose:@"Validating redirect URL", [url description], nil];
	
	NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
	if (!comp) {
		MC_ERR(error, @"Invalid redirect URI", 0)
		return NO;
	}
	
	// did we get a code?
	NSDictionary *query = [[self class] paramsFromQuery:comp.percentEncodedQuery];
	NSString *retCode = query[@"code"];
	if (retCode) {
		if ([query[@"state"] isEqualToString:self.state]) {
			self.code = retCode;
			return YES;
		}
		
		MC_ERR(error, @"Invalid \"state\" was returned, cannot continue", 0)
	}
	
	// server responded with an error
	else if (error != NULL) {
		*error = [[self class] errorForAccessTokenErrorResponse:query];
	}
	
	return NO;
}


@end
