MCOAuth2
========

OAuth2 classes for a modern Objective-C environment.
This is more of an academic exercise and very much WiP.
Here is a very nice explanation of OAuth's basics: [The OAuth Bible](http://oauthbible.com/#oauth-2-three-legged).

The code in this repo requires OS X 10.9+ or iOS 7+, with ARC enabled.

Flows
-----

#### Code Grant

For a full OAuth 2 code grant flow you want to use the `MCOAuth2CodeGrant` class.
This flow is typically used by applications that can guard their secrets, like server-side apps, and not in distributed binaries.

#### Implicit Grant

An implicit grant is suitable for apps that are not capable of guarding their secret, such as distributed binaries or client-side web apps.
Use the `MCOAuth2ImplicitGrant` class to receive a token and perform requests.


Test App
--------

There is a simple [Mac App](https://github.com/p2/MCOAuth2App) that uses this repo, you can use it as an example implementation.
