//
//  MCOAuth2ImplicitGrant.m
//  MCOAuth2App
//
//  Created by Pascal Pfiffner on 5/5/14.
//  Copyright (c) 2014 Pascal Pfiffner. All rights reserved.
//

#import "MCOAuth2ImplicitGrant.h"


@interface MCOAuth2ImplicitGrant ()

@property (strong, nonatomic, readwrite) NSURL *authorizeURL;
@property (copy, nonatomic, readwrite) NSString *authorizePath;

/** The state is sent to the server when requesting a token code, we internally generate a UUID. */
@property (copy, nonatomic) NSString *state;

@end


@implementation MCOAuth2ImplicitGrant


- (id)initWithBaseURL:(NSURL *)base
			authorize:(NSString *)authorize
			 clientId:(NSString *)clientId
			 redirect:(NSString *)redirect
				scope:(NSString *)scope
{
	if ((self = [super initWithBaseURL:base apiURL:nil])) {
		self.authorizePath = authorize;
		
		self.clientId = clientId;
		self.redirect = redirect;
		self.state = [[self class] newUUID];
		
		if (self.baseURL && _authorizePath && _clientId && _redirect) {
			NSDictionary *params = @{
				@"client_id": _clientId,
				@"response_type": @"token",
				@"redirect_uri": _redirect ?: [NSNull null],
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



#pragma mark - OAuth Actions

- (void)handleRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback
{
	// TODO: working here
	NSLog(@"url: %@", url);
}


@end