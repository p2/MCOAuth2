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
	}
	return self;
}



#pragma mark - OAuth Dance

- (NSURL *)authorizeURLWithRedirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params
{
	if ([params count] > 0) {
		NSMutableDictionary *mute = [params mutableCopy];
		mute[@"response_type"] = @"code";
		[mute addEntriesFromDictionary:params];
		params = [mute copy];
	}
	else {
		params = @{@"response_type": @"code"};
	}
	
	return [self urlWithBase:self.authorizeURL redirect:redirect scope:scope additionalParameters:params];
}

- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL, NSError *))callback
{
	NSError *error = nil;
	NSString *code = nil;
	if (![self validateRedirectURL:url error:&error]) {
		if (callback) {
			callback(NO, error);
		}
		return;
	}
	
	[self exchangeCodeForToken:code callback:callback];
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
	
	// do we have the exchange URL and other params?
	if (!_tokenURL) {
		if (callback) {
			NSError *error = nil;
			MC_ERR(&error, @"I'm missing `tokenURL`, please configure me correctly", 0);
			callback(NO, error);
		}
		return;
	}
	
	NSDictionary *params = @{
		@"grant_type": @"authorization_code",
		@"code": _code
	};
	NSURL *url = [self urlWithBase:_tokenURL redirect:self.redirect scope:self.scope additionalParameters:params];
	
	NSMutableURLRequest *post = [[NSMutableURLRequest alloc] initWithURL:url];
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



#pragma mark - Utilities

- (BOOL)validateRedirectURL:(NSURL *)url error:(NSError **)error
{
	NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
	if (!comp) {
		MC_ERR(error, @"Invalid redirect URI", 0)
		return NO;
	}
	
	NSDictionary *query = [[self class] paramsFromQuery:comp.query];
	
	// did we get a code?
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
