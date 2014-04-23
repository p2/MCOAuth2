//
//  MCOAuth2.m
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

#import "MCOAuth2.h"


@implementation MCOAuth2

- (id)initWithBaseURL:(NSURL *)base
{
	NSParameterAssert(base);
	if ((self = [super init])) {
		self.baseURL = base;
	}
	return self;
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
		[query addObject:[NSString stringWithFormat:@"%@=%@", key, obj]];		// NSURLComponents will correctly encode the parameter string
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


@end
