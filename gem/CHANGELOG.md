## 3.2.1, 16-Feb-2025

The conditional login return-via-referrer mechanism never really worked, so instead have the login status indicator link generate a return-to URL in the query string instead and forward that, if present, in preference.

## 3.2.0, 15-Feb-2025

Introduces the user change handler mechanism, a scheme whereby an external application tells Hub about a Rake task that the application has implemented, through which Hub can inform if of changes to a user's e-mail address or "real" name. See the gem's `README.md` for details, under "Applications with an existing user model".

## 3.1.0, 14-Feb-2025

Environment variable `HUB_IDLE_TIME_LIMIT` can be used to override the idle timeout, with a value expressed in seconds. It must be set in the environment of any application using Hub, including the Hub application itself.

## 3.0.3, 10-Feb-2025

Change JavaScript code used for the login indicator so that simpler engines such as [Duktape](https://duktape.org) can run it. Operates correctly in script-enabled [NetSurf](https://www.netsurf-browser.org) now.

## 3.0.2, 04-Feb-2025

Fixes a bug that could cause cookie deletions for login state indication to sometimes fail to work as expected.

## 3.0.0, 28-Jan-2025 and 3.0.1, 03-Feb-2025

* The Hub "login indication" URL approach is now dropped, so layout templates **should be updated.**

In Hub v1 and v2, login indication was done via an image that was served by the Hub application itself, wrapped in a link that visited a "conditional login" endpoint which stored the return-to URL, ensured HTTPS was in use and visited either the log in, or log out page as required. In client applications it looked a bit like this:

```html
<a class="img" href="<%= ENV['HUB_PATH_PREFIX'] %>/account/login_conditional">
  <img src="<%= ENV['HUB_PATH_PREFIX'] %>/account/login_indication" alt="Account" height="22" width="90" />
</a>
```

This dates back to a time when CSS support was not that widespread and RISC OS Open needed the web site to work well on web browsers available at the time. Things have improved considerably since then, so now a cleaner, pure CSS solution is used. This requires no image fetch via the Hub application. Just use:

```ruby
<%= hubssolib_account_link() %>
```

...in place of the markup above. You probably want to add some supporting CSS too; for example:

```css
#hubssolib_login_indication a#hubssolib_logged_in_link,
#hubssolib_login_indication a#hubssolib_logged_out_link {
  display:         block;
  text-align:      center;
  text-decoration: none;
  font:            sans-serif;
  font-size:       10pt;
  line-height:     20px;
  height:          20px;
  width:           88px;
  border:          1px solid #ccc;
}

#hubssolib_login_indication a#hubssolib_logged_in_link {
  color:        #050;
  border-color: #050;
  background:   #efe;
}

#hubssolib_login_indication a#hubssolib_logged_out_link {
  color:        #500;
  border-color: #500;
  background:   #fee;
}

#hubssolib_login_indication a#hubssolib_login_noscript {
  text-decoration: none;
}
```

Version 3.0.1 patches the system to make sure that the correct current login state is shown even if a browser has a page cached. To achieve this, JavaScript is used to check cookie state and update the indication on-the-fly. There is a `noscript` fallback that uses the old, inefficient `login_indication` image mechanism - just in case. The CSS styles above are designed to match those images, though of course, they certainly don't have to!



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
