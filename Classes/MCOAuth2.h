//
//  MCOAuth2.h
//  Ossus
//
//  Created by Pascal Pfiffner on 4/22/14.
//

@import Foundation;


/**
 *  An abstract superclass for our simple OAuth2 client.
 */
@interface MCOAuth2 : NSObject

/** The base URL, all paths will be relative to this one. */
@property (strong, nonatomic) NSURL *baseURL;

/** Designated initializer. */
- (id)initWithBaseURL:(NSURL *)base;


#pragma mark Utilities

/** Return a new UUID. */
+ (NSString *)newUUID;

/** Create a query string from a dictionary. */
+ (NSString *)queryStringFor:(NSDictionary *)params;

/** Parse a query string into a dictionary. */
+ (NSDictionary *)paramsFromQuery:(NSString *)query;

@end


#ifndef MC_ERR
# define MC_ERR(mc_err_p, mc_err_s, mc_err_c) if (mc_err_p != NULL && mc_err_s) {\
		*mc_err_p = [NSError errorWithDomain:NSCocoaErrorDomain code:(mc_err_c ? mc_err_c : 0) userInfo:@{NSLocalizedDescriptionKey: mc_err_s}];\
	}\
	else {\
		NSLog(@"%s (line %d) ignored error: %@", __PRETTY_FUNCTION__, __LINE__, mc_err_s);\
	}
#endif
