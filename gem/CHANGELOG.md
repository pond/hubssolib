## 2.1.0, 01-Jul-2022

* Use `HUB_QUIET_SERVER=yes ...` to quieten `$stdout` output from Hub server.
* Test coverage fixed (overlooked in v2.0.0 release).
* Maintenance `bundle update`.
* A few minor tidy-ups in the implementation.

## Version 1.0.0 -> Version 2.0.0, 19-Apr-2020

The public interface to applications is generally unchanged, but the cookie storage mechanism has been improved and is not compatible with v1 of Hub. You will need to use the newer Hub application, server and gem, but hopefully will find you don't need to change anything with your integrated applications.

* The Hub random data file is no longer necessary.
* The (internal) `HubSsoLib::Crypto` class has been completely deleted in favour of `SecureRandom.uuid` key rotation, HTTPS and insisting that the Hub server only ever runs on Unix domain sockets.
* The (internal) `hubssolib_get_secure_cookie_data`, `hubssolib_set_secure_cookie_data`, `hubssolib_get_user_data` and `hubssolib_set_user_data` methods are no longer needed and have been removed.
* The (internal) Hub server factory `get_session` factory method is renamed to `get_hub_session_proxy` (since that's what it actually does) and `enumerate_sessions` is renamed `enumerate_hub_sessions` as part of a wider rename that removed potential ambiguity in the application controller namespace between local variables called `session` and the Rails `session`.
