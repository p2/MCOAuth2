//
//  MCOAuth2ImplicitGrant.m
//  MCOAuth2App
//
//  Created by Pascal Pfiffner on 5/5/14.
//  Copyright (c) 2014 Pascal Pfiffner. All rights reserved.
//

#import "MCOAuth2ImplicitGrant.h"


@implementation MCOAuth2ImplicitGrant


#pragma mark - OAuth Actions

- (NSURL *)authorizeURLWithRedirect:(NSString *)redirect scope:(NSString *)scope additionalParameters:(NSDictionary *)params
{
	if ([params count] > 0) {
		NSMutableDictionary *mute = [params mutableCopy];
		mute[@"response_type"] = @"token";
		[mute addEntriesFromDictionary:params];
		params = [mute copy];
	}
	else {
		params = @{@"response_type": @"token"};
	}
	
	return [self authorizeURLWithBase:self.authorizeURL redirect:redirect scope:scope additionalParameters:params];
}

- (void)handleRedirectURL:(NSURL *)url callback:(void (^)(BOOL didCancel, NSError *error))callback
{
	[self logIfVerbose:@"Handling redirect URL", [url description], nil];
	NSError *error = nil;
	
	// exctract token from URL fragment
	NSURLComponents *comp = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
	if (comp.fragment) {
		NSDictionary *params = [[self class] paramsFromQuery:comp.fragment];
		NSString *token = params[@"access_token"];
		if ([token length] > 0) {
			NSAssert([@"bearer" isEqualToString:[params[@"token_type"] lowercaseString]], @"Only supporting \"bearer\" tokens for now");
			
			// got a token, use it if state checks out
			if ([params[@"state"] isEqualToString:self.state]) {
				self.accessToken = token;
				[self logIfVerbose:@"Successfully extracted access token", nil];
			}
			else {
				NSString *errstr = [NSString stringWithFormat:@"Invalid state \"%@\", will not use the token", params[@"state"]];
				MC_ERR(&error, errstr, 0)
			}
		}
		else {
			error = [[self class] errorForAccessTokenErrorResponse:params];
		}
	}
	else {
		NSString *errstr = [NSString stringWithFormat:@"Invalid redirect URL: %@", url];
		MC_ERR(&error, errstr, 0)
	}
	
	// log, if needed, then call the callback
	if (error) {
		[self logIfVerbose:@"Error handling redirect URL:", [error localizedDescription], nil];
	}
	if (callback) {
		callback(NO, error);
	}
}


@end
