## 2.1.0 (11-Apr-2020)

Stop using Google captcha solutions; they don't play well with e.g. NetSurf. Rewritten with a lighter weight alternative - https://github.com/markets/invisible_captcha plus a simple home-brew maths question addition.

Account list view now has a simple search function, at long last.

If an HTTP `Referer` header is set by the application redirecting to Hub via `account/login_conditional`, the Hub session cookie will remember the referrer URI and return there after a user signs in. Previously, only automated redirect-to-log-in events caused by integrated applications being asked to perform user actions that required a signed-in user would do this; explicitly following a link to the Hub log-in page would not.

Requires Hub gem version 2.0.0 or later.

## 2.0.0 (01-May-2019)

Rebuilt inside a new Rails 5.2.3 shell. Requires Hub gem version 1.0.0 or later.

## 1.0.2 (16-Apr-2016)

Updated and customised reCaptcha code for V2 Google reCaptcha use.

## 1.0.1 (30-Aug-2011)

Added reCaptcha verification to the sign-up form via the following, installed as a plugin:

* https://github.com/ambethia/recaptcha

This was required because the ROOL Hub installation started to get hit by literally hundreds of bogus signups from bots. JavaScript-free operation is *just about* possible but very confusing and awkward.

## 1.0.0 (31-Jan-2011)

Updated release based on Rails 2.3.10 and field-proven internals from the RISC OS Open web site. Expected to be served by Phusion Passenger - see:

* http://modrails.org/

Using services like Passenger, or equivalents, eliminates the need for static configuration related to the location of Hub in the server's document tree.

Requires Hub gem version 0.2.6 or later.

## 0.2.1 (25-Feb-2009)

Original public release on "http://hub.pond.org.uk/". Used for several years on the RISC OS Open web site at "http://www.riscosopen.org/". Developed on Rails 1.1.6 and served by LigHTTPd.

Due to the way that Rails and the expected server environment work, static configuration is needed to specify the location of Hub within the web server's document tree (typically, Hub is served from public-facing location "/hub").

Requires Hub gem version 0.2.6 or later.
