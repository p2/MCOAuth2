//
//  MCOAuth2.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2.h"


@interface MCOAuth2 ()

@property (copy, nonatomic, readwrite) NSDictionary *settings;
@property (copy, nonatomic, readwrite) NSString *redirect;
@property (copy, nonatomic, readwrite) NSString *scope;

@end


@implementation MCOAuth2


- (id)initWithSettings:(NSDictionary *)settings
{
	NSParameterAssert(settings);
	if ((self = [super init])) {
		self.settings = settings;
		self.clientId = settings[@"client_id"];
		
		if ([settings[@"api_uri"] length] > 0) {
			self.apiURL = [NSURL URLWithString:settings[@"api_uri"]];
		}
		if ([settings[@"authorize_uri"] length] > 0) {
			self.authorizeURL = [NSURL URLWithString:settings[@"authorize_uri"]];
		}
	}
	return self;
}



#pragma mark - OAuth Actions

- (NSURL *)authorizeURLWithRedirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params;
{
	@throw [NSException exceptionWithName:@"MCOAuth2AbstractClassUse" reason:@"No no, this is not the class you're looking for" userInfo:nil];
}

- (NSURL *)urlWithBase:(NSURL *)url redirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params
{
	if (!self.clientId) {
		@throw [NSException exceptionWithName:@"MCOAuth2IncompletSetup" reason:@"I do not yet have a client id, cannot construct an authorize URL" userInfo:nil];
	}
	if (!url) {
		NSLog(@"I need a base URL to create the full URL");
		return nil;
	}
	
	if (!redirect) {
		redirect = [_settings[@"redirect_uris"] firstObject];
		if (!redirect) {
			return nil;
		}
	}
	self.redirect = redirect;
	
	if (scope) {
		self.scope = scope;
	}
	if (!_state) {
		self.state = [[self class] newUUID];
	}
	
	NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
	NSAssert([comp.scheme isEqualToString:@"https"], @"You MUST use HTTPS!");
	
	// compose the URL
	NSMutableDictionary *urlParams = [@{
		@"client_id": self.clientId,
		@"redirect_uri": _redirect,
		@"scope": _scope ?: (_settings[@"scope"] ?: [NSNull null]),
		@"state": _state
	} mutableCopy];
	
	[urlParams addEntriesFromDictionary:params];
	comp.query = [[self class] queryStringFor:urlParams];
	
	NSURL *final = comp.URL;
	NSAssert(final, @"Unable to create a valid URL from components. Components: %@", comp);
	
	return final;
}

- (void)exchangeTokenWithRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback;
{
	@throw [NSException exceptionWithName:@"MCOAuth2AbstractClassUse" reason:@"Oh snap, should have used a subclass" userInfo:nil];
}



#pragma mark - Resource Requests

- (void)requestJSONResource:(NSString *)restPath callback:(void (^)(id jsonObject, NSError *error))callback
{
	NSParameterAssert(restPath);
	if (!self.accessToken) {
		if (callback) {
			NSError *error = nil;
			MC_ERR(&error, @"I don't yet have an access token, cannot request data", 0)
			callback(NO, error);
		}
		return;
	}
	
	// compose the URL
	NSURLComponents *comp = [NSURLComponents componentsWithURL:self.apiURL resolvingAgainstBaseURL:YES];
	comp.path = [comp.path ?: @"" stringByAppendingPathComponent:restPath];
	
	NSMutableURLRequest *get = [[NSMutableURLRequest alloc] initWithURL:comp.URL];
	[get setValue:@"application/json" forHTTPHeaderField:@"Accept"];
	[get setValue:[NSString stringWithFormat:@"Bearer %@", self.accessToken] forHTTPHeaderField:@"Authorization"];
	
	// send the GET request
	[NSURLConnection sendAsynchronousRequest:get queue:[NSOperationQueue mainQueue] completionHandler:^(NSURLResponse *response, NSData *data, NSError *connectionError) {
		NSError *error = connectionError;
		if (!error) {
			NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
			if ([http isKindOfClass:[NSHTTPURLResponse class]]) {
				if (200 == http.statusCode) {
					
					// success, deserialize JSON and call the callback
					NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
					if (callback) {
						callback(json, error);
					}
					return;
				}
				
				// HTTP error
				MC_ERR(&error, [NSHTTPURLResponse localizedStringForStatusCode:http.statusCode], http.statusCode)
			}
		}
		
		if (callback) {
			callback(nil, error ?: [NSError errorWithDomain:NSCocoaErrorDomain code:0 userInfo:@{NSLocalizedDescriptionKey: @"Unknown response error"}]);
		}
	}];
}



#pragma mark - Utilities

+ (NSString *)newUUID
{
	CFUUIDRef uuid = CFUUIDCreate(NULL);
	NSString *str = (__bridge_transfer NSString *)CFUUIDCreateString(NULL, uuid);
	CFRelease(uuid);
	
	return str;
}

+ (NSString *)queryStringFor:(NSDictionary *)params
{
	NSMutableArray *query = [NSMutableArray arrayWithCapacity:[params count]];
	[params enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
		if ([NSNull null] != obj) {
			[query addObject:[NSString stringWithFormat:@"%@=%@", key, obj]];		// NSURLComponents will correctly encode the parameter string
		}
	}];
	
	return [query componentsJoinedByString:@"&"];
}


+ (NSDictionary *)paramsFromQuery:(NSString *)query
{
	NSArray *queryParts = [query componentsSeparatedByString:@"&"];
	NSMutableDictionary *params = [NSMutableDictionary dictionaryWithCapacity:[queryParts count]];
	for (NSString *queryPart in queryParts) {
		NSArray *parts = [queryPart componentsSeparatedByString:@"="];
		if (2 == [parts count]) {
			params[parts[0]] = parts[1];
		}
	}
	
	return params;
}

+ (NSError *)errorForAccessTokenErrorResponse:(NSDictionary *)params
{
	NSString *message = nil;
	
	// "error_description" is optional, we prefer it if it's present
	NSString *err_msg = params[@"error_description"];
	if ([err_msg length] > 0) {
		message = [err_msg stringByReplacingOccurrencesOfString:@"+" withString:@" "];
	}
	
	// the "error" response is required for error responses
	NSString *err_code = params[@"error"];
	if ([err_code length] > 0 && 0 == [message length]) {
		if ([err_code isEqualToString:@"invalid_request"]) {
			message = @"The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.";
		}
		else if ([err_code isEqualToString:@"unauthorized_client"]) {
			message = @"The client is not authorized to request an access token using this method.";
		}
		else if ([err_code isEqualToString:@"access_denied"]) {
			message = @"The resource owner or authorization server denied the request.";
		}
		else if ([err_code isEqualToString:@"unsupported_response_type"]) {
			message = @"The authorization server does not support obtaining an access token using this method.";
		}
		else if ([err_code isEqualToString:@"invalid_scope"]) {
			message = @"The requested scope is invalid, unknown, or malformed.";
		}
		else if ([err_code isEqualToString:@"server_error"]) {
			message = @"The authorization server encountered an unexpected condition that prevented it from fulfilling the request.";
		}
		else if ([err_code isEqualToString:@"temporarily_unavailable"]) {
			message = @"The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server";
		}
		else {
			message = [NSString stringWithFormat:@"Authorization error: %@", err_code];
		}
	}
	
	// unknown error
	if (0 == [message length]) {
		message = @"Unknown error";
	}
	
	NSMutableDictionary *userInfo = params ? [params mutableCopy] : [NSMutableDictionary dictionaryWithCapacity:1];
	userInfo[NSLocalizedDescriptionKey] = message;
	
	return [NSError errorWithDomain:@"MCOAuth2ErrorDomain" code:600 userInfo:userInfo];
}


@end
