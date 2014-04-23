//
//  MCOAuth2ThreeLegged.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2ThreeLegged.h"


@interface MCOAuth2ThreeLegged ()

@property (strong, nonatomic, readwrite) NSURL *authorizeURL;
@property (copy, nonatomic) NSString *exchangePath;

@property (copy, nonatomic) NSString *clientId;
@property (copy, nonatomic) NSString *clientSecret;
@property (copy, nonatomic) NSString *redirect;
@property (copy, nonatomic) NSString *state;

@property (copy, nonatomic) NSString *code;
@property (copy, nonatomic) NSString *accessToken;
@property (copy, nonatomic) NSString *refreshToken;

@end


@implementation MCOAuth2ThreeLegged


- (id)initWithBaseURL:(NSURL *)base authorize:(NSString *)authorize exchange:(NSString *)exchange clientId:(NSString *)clientId secret:(NSString *)secret redirect:(NSString *)redirect scope:(NSString *)scope
{
	NSParameterAssert(authorize);
	NSParameterAssert(exchange);
	NSParameterAssert(clientId);
	NSParameterAssert(secret);
	NSParameterAssert(redirect);
	
	if ((self = [super initWithBaseURL:base])) {
		self.exchangePath = exchange;
		
		self.clientId = clientId;
		self.clientSecret = secret;
		self.redirect = redirect;
		self.state = [[self class] newUUID];
		
		NSDictionary *params = @{
			@"client_id": clientId,
			@"response_type": @"code",
			@"redirect_uri": redirect,
			@"scope": scope ?: @"basic",
			@"state": _state
		};
		
		NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
		NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
		comp.path = authorize;
		comp.query = [[self class] queryStringFor:params];
		
		self.authorizeURL = comp.URL;
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
	NSURLComponents *comp = [NSURLComponents componentsWithURL:self.baseURL resolvingAgainstBaseURL:YES];
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
		MC_ERR(error, @"Invalid callback URI", 0)
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
	
	NSString *err_msg = query[@"error_description"] ?: @"Did not receive a code, cannot continue";
	MC_ERR(error, err_msg, 0)
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
	comp.path = _exchangePath;
	
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
