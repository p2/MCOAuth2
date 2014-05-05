//
//  MCOAuth2ThreeLegged.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2AuthCodeGrant.h"


@interface MCOAuth2AuthCodeGrant ()

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
		self.state = [[self class] newUUID];
		
		if (self.baseURL && _authorizePath && _clientId && _redirect) {
			NSDictionary *params = @{
				@"client_id": _clientId,
				@"response_type": @"code",
				@"redirect_uri": _redirect,
				@"scope": scope ?: [NSNull null],
				@"state": _state
			};
			
			NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
			NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
			comp.path = [comp.path ?: @"" stringByAppendingPathComponent:authorize];
			comp.query = [[self class] queryStringFor:params];
			
			self.authorizeURL = comp.URL;
			NSAssert(_authorizeURL, @"Unable to create a valid URL from components. This usually happens when you supply paths without leading slash. Components: %@", comp);
		}
	}
	return self;
}



#pragma mark - Requesting Resources

- (void)requestJSONResource:(NSString *)restPath callback:(void (^)(id jsonObject, NSError *error))callback
{
	NSParameterAssert(restPath);
	if (!_accessToken) {
		if (callback) {
			NSError *error = nil;
			MC_ERR(&error, @"I don't yet have an access token, cannot request data", 0)
			callback(NO, error);
		}
		return;
	}
	
	// compose the URL
	NSURLComponents *comp = [NSURLComponents componentsWithURL:self.apiURL resolvingAgainstBaseURL:YES];
	comp.path = restPath;
	
	NSMutableURLRequest *get = [[NSMutableURLRequest alloc] initWithURL:comp.URL];
	[get setValue:[NSString stringWithFormat:@"Bearer %@", _accessToken] forHTTPHeaderField:@"Authorization"];
	
	// send the GET request
	[NSURLConnection sendAsynchronousRequest:get queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
		NSError *error = connectionError;
		if (!error) {
			NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
			if ([http isKindOfClass:[NSHTTPURLResponse class]] && 200 == http.statusCode) {
				
				// success, store token
				NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
				if (json) {
					if (callback) {
						callback(json, nil);
					}
					return;
				}
			}
		}
		
		if (callback) {
			callback(nil, error ?: [NSError errorWithDomain:NSCocoaErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unknown response error"}]);
		}
	}];
}



#pragma mark - OAuth Dance

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
	
	NSDictionary *query = [[self class] paramsFromQuery:comp.query];
	
	// did we get a code?
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
