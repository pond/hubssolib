## 3.0.0, 28-Jan-2025

* The Hub "login indication" URL approach is now dropped, so layout templates **must be updated.**

In Hub v1 and v2, login indication was done via an image that was served by the Hub application itself, wrapped in a link that visited a "conditional login" endpoint which stored the return-to URL, ensured HTTPS was in use and visited either the log in, or log out page as required. In client applications it looked a bit like this:

```html
  <a class="img" href="<%= ENV['HUB_PATH_PREFIX'] %>/account/login_conditional">
    <img src="<%= ENV['HUB_PATH_PREFIX'] %>/account/login_indication" alt="Account" height="22" width="90" />
  </a>
```

This dates back to a time when CSS support was not that widespread and RISC OS Open needed the web site to work well on web browsers available at the time. Things have improved enormously since then, so now a cleaner, pure CSS solution is used. This has the enormous advantage of requiring no image fetch request-response into the Hub application. Just use:

```ruby
<%= hubssolib_account_link() %>
```

...in place of the markup above.



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
