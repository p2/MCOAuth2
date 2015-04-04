//
//  MCOAuth2CodeGrant.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2AuthCodeGrant.h"


@interface MCOAuth2AuthCodeGrant ()

@property (copy, nonatomic) NSDictionary *urlParams;
@property (strong, nonatomic, readwrite) NSURL *authorizeURL;
@property (copy, nonatomic, readwrite) NSString *authorizePath;

/** The state is sent to the server when requesting a token code, we internally generate a UUID. */
@property (copy, nonatomic) NSString *state;

@end


@implementation MCOAuth2AuthCodeGrant


- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
				token:(NSString *)token
			 clientId:(NSString *)clientId
			   secret:(NSString *)secret
			 redirect:(NSString *)redirect
				scope:(NSString *)scope
{
	if ((self = [super initWithBaseURL:base apiURL:nil])) {
		self.authorizePath = authorize;
		self.tokenPath = token;
		
		self.clientId = clientId;
		self.clientSecret = secret;
		self.redirect = redirect;
		self.state = [[[self class] newUUID] substringToIndex:8];
		
		if (self.baseURL && _authorizePath && _clientId && _redirect) {
			self.urlParams = @{
				@"client_id": _clientId,
				@"response_type": @"code",
				@"redirect_uri": _redirect,
				@"scope": scope ?: [NSNull null],
				@"state": _state
			};
			
			NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
			NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
			comp.path = [comp.path ?: @"" stringByAppendingPathComponent:authorize];
			comp.query = [[self class] queryStringFor:_urlParams];
			
			self.authorizeURL = comp.URL;
			NSAssert(_authorizeURL, @"Unable to create a valid URL from components. Components: %@", comp);
		}
	}
	return self;
}



#pragma mark - OAuth Dance

- (NSURL *)authorizeURLWithAdditionalParameters:(NSDictionary *)params
{
	if (0 == [params count]) {
		return _authorizeURL;
	}
	
	NSAssert(_urlParams, @"Must possess URL params after initialization");
	NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
	NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
	comp.path = [comp.path ?: @"" stringByAppendingPathComponent:_authorizePath];
	
	NSMutableDictionary *mute = [_urlParams mutableCopy];
	[mute addEntriesFromDictionary:params];
	comp.query = [[self class] queryStringFor:mute];
	
	NSURL *url = comp.URL;
	NSAssert(url, @"Unable to create a valid URL from components. Components: %@", comp);
	
	return url;
}


/**
 *  Validates the params in the passed-in redirect URL.
 */
- (BOOL)validateRedirectURL:(NSURL *)url error:(NSError **)error
{
	NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
	if (!comp) {
		MC_ERR(error, @"Invalid redirect URI", 0)
		return NO;
	}
	
	// did we get a code?
	NSDictionary *query = [[self class] paramsFromQuery:comp.percentEncodedQuery];
	NSString *code = query[@"code"];
	if (code) {
		if ([query[@"state"] isEqualToString:_state]) {
			self.code = code;
			return YES;
		}
		
		MC_ERR(error, @"Invalid \"state\" was returned, cannot continue", 0)
		return NO;
	}
	
	// error response
	if (error != NULL) {
		*error = [[self class] errorForAccessTokenErrorResponse:query];
	}
	return NO;
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

- (void)exchangeCodeForToken:(NSString *)code callback:(void (^)(BOOL, NSError *))callback
{
	self.code = code;
	
	// do we have a code?
	if (!_code) {
		if (callback) {
			NSError *error = nil;
			MC_ERR(&error, @"I don't have a code to exchange, let the user authorize first", 0);
			callback(NO, error);
		}
		return;
	}
	
	// create a request for token exchange
	NSDictionary *params = @{
		@"grant_type": @"authorization_code",
		@"client_id": _clientId,
		@"client_secret": _clientSecret,
		@"code": _code,
		@"redirect_uri": _redirect
	};
	
	NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
	NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
	comp.path = [comp.path ?: @"" stringByAppendingPathComponent:_tokenPath];
	
	NSMutableURLRequest *post = [[NSMutableURLRequest alloc] initWithURL:comp.URL];
	[post setHTTPMethod:@"POST"];
	[post setValue:@"application/x-www-form-urlencoded; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
	[post setHTTPBody:[[[self class] queryStringFor:params] dataUsingEncoding:NSUTF8StringEncoding]];
	
	// perform the exchange
	[NSURLConnection sendAsynchronousRequest:post queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
		NSError *error = connectionError;
		if (!error) {
			NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
			if ([http isKindOfClass:[NSHTTPURLResponse class]] && 200 == http.statusCode) {
				
				// success, store token
				NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
				if (json) {
					self.accessToken = json[@"access_token"];
					self.refreshToken = json[@"refresh_token"];
					
					if (callback) {
						callback(NO, nil);
					}
					return;
				}
			}
		}
		
		if (callback) {
			callback(NO, error ?: [NSError errorWithDomain:NSCocoaErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unknown connection error"}]);
		}
	}];
}


@end
