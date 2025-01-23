# Welcome to Hub

Hub is a single sign-on solution for multiple Ruby On Rails applications which are running under the **same domain** but different paths within that domain. When a user signs into Hub, they don't have to individually sign in to other applications on the domain provided that those applications are integrated with the Hub mechanism. This requires software development effort on behalf of the application installer or application developer.

Hub provides a solution to a different problem from that addressed by cross domain single sign-on solutions such as OpenID, wherein a user on some origin web site signs into some third party service on another domain. Hub is much simpler; there are no scopes, popups, third party cookies or similar, because everything is on *one* domain so the Hub core session cookie is available across all Rails applications therein.

Hub was designed for and is tailored for use on the [RISC OS Open (ROOL)](https://www.riscosopen.org/) web site. Often, the main branch is out of date - check for feature branches for newer versions.

## Components

There are three components, each with their own `README.md`:

* The hub [gem](gem/README.md)
* The hub [server](server/README.md) (which is a separate command rather than being bundled in as a gem binary, really just to make it more visible and easier to modify)
* The Rails hub [application](app/hub/README.md)

Applications use the gem API to talk to the server and get information about a current user (if there is one). The Hub application is the sign-on interface and account management portal which also uses the gem and server. While the application provides read/write access to the data layer and sign-on state, all other Hub gem clients have read-only access to the current user state.
