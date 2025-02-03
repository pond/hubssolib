# Hub single sign-on

Hub is a Ruby On Rails application with accompanying library gem which manages user accounts for a web site. Its main use is for sites that run more than one Rails application within a single domain. Through integration with the Hub library gem, applications share Hub user details so that a user only has to create one account and log in or out of one place. Without Hub, users have to create and manage individual accounts for individual applications. Hub is therefore a single sign-on mechanism.

Applications require modifications to use Hub. Applications that already have the concept of users and accounts must be modified with some care, because the application's own account mechanism must be replaced or overlaid with the single sign-on alternative. Applications that have no account mechanism are much simpler to modify. You may wish to add Hub support to such applications so that users must create accounts to perform certain actions, such as posting to a forum or blog that might otherwise be completely open to the public — and therefore completely open to spam.

Hub has three main components. The Hub application handles users creating accounts, logging in and out and managing their account settings, through an ActiveRecord database connection and the library gem. User information stored securely in the database while the gem is used to record details when a user logs in or discard those details when a user logs out. The gem does this by sending objects to or reading objects from the third component, a small distributed Ruby server. Running on Unix domain sockets, the server allows all Hub-integrated Rails applications to share information on a logged in user without needing secondary ActiveRecord connections to the Hub database or any detailed knowledge of Hub's user account model. Everything is hidden by the Hub library gem API.

The Hub core is very distantly based on the [Acts as Authenticated](https://web.archive.org/web/20061126081805/http://technoweenie.stikipad.com/plugins/show/Acts+as+Authenticated) shell.

## Installation

### Downloading

Presently, only a version of Hub with views styled for the RISC OS Open web site is available. In future I hope to add a more generic and more easily customised version.

The latest version of the Hub application is available at:

[https://github.com/pond/hub](https://github.com/pond/hub)

The latest version of the Hub gem source code is available at:

[https://github.com/pond/hubssolib](https://github.com/pond/hubssolib)

### The Hub library gem

Include in a project by adding this to your `Gemfile`:

```ruby
gem 'hubssolib', '~> 3.0', require: 'hub_sso_lib'
```

### The DRb server

The Hub DRb server consists of a small wrapper Ruby script which does most of its work using the Hub gem. To run the server, you need to first specify a DRb connection URI in the `HUB_CONNECTION_URI` environment variable. Usually, this is a Unix domain socket and so lives in a location of your choice in the local filesystem. Run the server by running `ruby` on the `hub_sso_server.rb` file in the Hub archive. For example:

```sh
HUB_CONNECTION_URI="drbunix:/home/username/sockets/.hub_drb"
export HUB_CONNECTION_URI
ruby /home/username/hubssolib/hub_sso_server.rb &
```

The default is to use a file `.hub_drb` in the root of the current user's home directory. If you specify a custom URI, note that it _MUST_ start with `drbunix:`; the hub server must not be run on an IP port for security reasons.

### The Hub application

Finally you can install the Hub application using whatever mechanism you prefer to application installation. See ample documentation elsewhere on the Web for information on installing Ruby On Rails applications — Hub itself contains the default rails README file with quite a lot of information in it.

Some configuration is needed using externally set environment variables. These are actually picked up by the Hub gem but you won't know what values to set until the application, DRb server and gem are all installed.

*   `HUB_CONNECTION_URI` — as already discussed, this holds a DRb URI giving the connection socket on which the server listens and to which clients connect; it defaults to `~/.hub_drb`.
*   `HUB_PATH_PREFIX` — sometimes the Hub Gem redirects to various locations within the Hub application. If you have installed the application away from document root, specify the prefix to put onto redirection paths here (otherwise, provide an empty string). For example, when redirecting to the `account` controller's `login` method, the path used is `HUB_PATH_PREFIX + '/account/login'`.
*   `HUB_BYPASS_SSL` - normally Hub sets cookies as secure-only in Production mode, requiring `https` fetches. This isn't enforced in e.g. development mode. If you want to allow insecure transport in Production, set `HUB_BYPASS_SSL` to `true`.

Usually, these are set up in a Web server configuration file as part of launching an FCGI process to host the Hub application.

Don't forget to set up the application's `database.yml` file in the usual fashion. use `rake db:migrate` to build the empty database structure.

## Cookies and domains

For Hub to work, your domains must _all match_. If one application on local development is fetched by `http://127.0.0.1` while another is on `http://locahost` or on something like `http://lvh.me`, an independent Hub session cookie will be generated by each application so things won't work; while Hub might think you're logged in, the integrating application will not.

A simple rule is to always use e.g. `http://127.0.0.1:3000` for the Hub application and `http://127.0.0.1:<other-port>` for other applications. So, for Hub, use:

```
bundle exec rails s -b 127.0.0.1 --port 3000
```

...and then launch integrating applications with:

```
HUB_BYPASS_SSL="true" HUB_PATH_PREFIX="http://127.0.0.1:3000" be rails s -b 127.0.0.1 --port <other-port>
```

...and fetch `http://127.0.0.1:<other-port>` in your web browser.

## Your application's session cookies

It is often a good idea to clear application cookies when Hub users log in or out, so that there is no stale session data hanging around. **The Hub application auto-clears *all* cookies *ending with* the name `app_session`** for this purpose. Therefore, your application might include a `config/initializers/session_store.rb` file that says something like this:

```ruby
# Be sure to restart your server when you modify this file.
Rails.application.config.session_store :cookie_store, key: 'yourappname_app_session'
```

This of course only applies if you're using cookies for your session data.

## Testing the installation

Visit your application in a Web browser and follow the links to sign up for a new account. To sign up, provide a name that will be displayed to users and a valid e-mail address. A confirmation message is sent to the address, containing a link that must be followed to activate the account. One created, users can log in and out of their accounts (with the possibility of sending a password reset request to their e-mail address in case they forget how to log in) and change their screen names. Users cannot change their recorded e-mail address — instead, they must create a new account under the new address.

As the first user of the Hub application, you test your installation by simply going through the sign-up process. The first account is automatically constructed with administrator privileges. If you are successfully able to visit the signup page, create your account, validate the signup using the confirmation e-mail message and subsequently log in or out of the new account, then Hub is correctly installed `:-)`

## Administrative use of the Hub application

Administrative account users are presented with extra options in the Hub control panel when they log on. You can list currently logged on users, list all users and modify account settings for any user, including deleting their accounts. Accounts have a list of _roles_ associated with them. Roles define whether or not a user has administrative privileges, webmaster privileges and so-on. When you integrate Hub with another application, you define exactly what these roles are because (as described below) you must assign lists of roles required to access protected controller actions.

Accounts can be assigned more than one role. Whether or not you ever want to do this will depend entirely on how you set up the roles required to access various controller actions as you integrate Hub with whichever applications you wish to work under the single sign-on mechanism.

## Integrating with applications

For full integration with Hub, particularly when it comes to showing or hiding things in application views, you need to know some of the Hub programmer interface. This API is described in detail later. First, we need to consider basic application integration issues, mostly revolving around modifying the application controllers. For more information on the interfaces used by the examples show, consult the detailed API documentation further down.

### Applications without an existing user model

Applications with no concept of user log-in are easy to integrate with Hub. Applications with only the concept of logging in for administrative purposes are similarly easy, provided your administrators do not mind having to log in using the application's own administrative mechanisms (so you basically treat the application as if it has no existing user model).

To integrate, add the Hub filters into `application.rb` just inside the definition of the `ApplicationController` class:

```ruby
# Hub single sign-on support.

require 'hub_sso_lib'
include HubSsoLib::Core
before_action :hubssolib_beforehand
after_action :hubssolib_afterwards</pre>
```

Within any controller which has actions which you wish to protect with Hub login, define a variable `@@hubssolib_permissions` and provide an accessor method for it. I'll deal with the accessor method first; for a controller called `FooController`, add the following to `foo_controller.rb`:

```ruby
def FooController.hubssolib_permissions
  @@hubssolib_permissions
end
```

More details are provided [below](#permissions) but, in brief, to define the permissions variable you create an instance of `HubSsoLib::Permissions`. The constructor is passed a hash. The hash keys are symbolized names of the controller actions you want to protect. The hash values are an array of privileges required to access the action, from a choice of one or more of `:admin`, `:webmaster`, `:privileged` and `:normal`. These relate to the roles you can assign to accounts as Hub administrator. For example:

```ruby
@@hubssolib_permissions = HubSsoLib::Permissions.new({
  :show => [ :admin, :webmaster, :privileged, :normal ],
  :edit => [ :admin, :webmaster ]
})
```

In this example, any user can access the controller's `show` action but only users with an administrator or webmaster role associated with their account can access the `edit` action.

A user's role(s) must match at least one of the privileges in the array for a given action — so even if your account has an administrator role (and _only_ an administrator role), it won't be able to access a protected action unless `:admin` is included in the array given within the hash to the `HubSsoLib::Permissions` constructor. For example:

```ruby
@@hubssolib_permissions = HubSsoLib::Permissions.new({
  :weblist => [ :webmaster, :privileged ]
})
```

Here, only accounts with the webmaster or privileged role associated can access the `weblist` action. If an account has only normal and/or administrative roles, it won't be allowed through.

### Applications with an existing user model

If you want to integrate Hub with an application which already has the concept of user accounts, logging in and logging out, there are two main approaches.

*   Remove the existing mechanism and replace with Hub (see above). Removal may be through actually deleting code, models and filters related to that mechanism or simply removing or blocking access to the parts of the application that deal with the users and dropping in Hub equivalents over a minimum amount of code, reducing overall changes to the application but leaving a less clean result.
*   Use a `before_action` in the application controller to run special code which you write, which maps a logged in Hub user to an existing application user. If the visitor is logged into Hub and no corresponding local application user account exists, one is created automatically based on the Hub account credentials.

Neither approach is problem-free and both require quite a lot of effort and testing. Automated testing is very hard because the modified application's behaviour depends upon logging in or out of Hub, which is running elsewhere. Unfortunately Rails doesn't offer a universally supported single sign-on mechanism so applications all use different approaches to user management; this means that there is no magic bullet to integration with Hub. You have to learn and understand the structure of the application being integrated and be prepared to make changes that are potentially quite extensive.

## Hub library API

The Hub component interfaces that should be used by application authors when integrating with the Hub single sign-on mechanism are described below. If you want a complete list of all public interfaces, consult the file `hub_sso_lib.rb` inside the Hub gem. All functions and classes therein are fully commented to describe the purpose of each class, along with the purpose, input parameters and return values of class methods and instance methods.

### Roles

Every Hub user account has assigned to it one or more _Roles_. For day to day use, roles are managed using the Hub application front-end. Role names are defined as symbols. Defined names are:

*   `:admin` — Administrators.
*   `:webmaster` — The site Webmaster.
*   `:privileged` — Normal users with privileges for certain actions.
*   `:normal` — Normal users. This role is assigned to new accounts by default.

When setting access permissions for actions in controllers (see next section), you specify the permissions in terms of the role names above. This means that you really define the true meaning of each of the four roles by their use within controllers. It isn't necessary to use all four roles or, if you want to add more, you can extend the `ROLES` constant in the `HubSsoLib::Roles` class inside `hub_sso_lib.rb` in the Hub gem.

### Permissions

Hub protects against access to actions in controller by using a `before_action` which checks to see if the controller defines a permissions structure. Permissions are defined as a hash, using action names as keys. The values define a role or roles permitted to access that action. Hub is based around the idea of a loose, permissive access mechanism. Actions omitted from the permissions hash _**are permitted**_ for general public access by default. Conversely, if an action is included but a particular role is not associated with it, that role is denied access. You can therefore allow a normal user to access an action which an administrator cannot use, by simply including the normal role but omitting the administrator role for that action.

Permitted roles are expressed as single symbols or their equivalent strings, or an array containing many symbols or equivalent strings. Most often, an array of symbols is used. To create a permissions object, instantiate `HubSsoLib::Permissions`. For example:

```ruby
@@hubssolib_permissions = HubSsoLib::Permissions.new({
  :show => [ :admin, :webmaster, :privileged, :normal ],
  :edit => [ :admin, :webmaster ]
})
```

Here, all roles are allowed to access the `show` action while only the `admin` and `webmaster` roles can access the `edit` action. Any other actions are unprotected, so even users who are not logged into to Hub can access them, along with any logged in Hub user regardless of the roles associated with their account.

The above line of code typically appears at the start of the class definition for the controller to which you are restricting access.

```ruby
class AccountController < ApplicationController

  @@hubssolib_permissions = HubSsoLib::Permissions.new({
    # ...permissions here...
  })

  # ...existing class contents here...
end
```

Having created the permissions object, you need to expose variable `@@hubssolib_permissions` to Hub in a way that it understands. To do this, create an instance method called `hubssolib_permissions` that just returns the variable:

```ruby
  def AccountController.hubssolib_permissions
    @@hubssolib_permissions
  end
```

So the full preamble in this example is:

```ruby
class AccountController < ApplicationController

  @@hubssolib_permissions = HubSsoLib::Permissions.new({
    ...permissions here...
  })

  def AccountController.hubssolib_permissions
    @@hubssolib_permissions
  end

  ...existing class contents here...
end
```

While you can ask a specific Permissions object whether or not an action is permitted for a given role or roles using the `permitted?` method ([see later](#permitted)), a more general purpose interface to achieve the same thing is provided in the `Core` module (see below). Use of the `Core` interface is strongly recommended.

### Core

The Hub `Core` module is usually included in `application.rb` as follows, just inside the `ApplicationController` class definition:

```ruby
# Hub single sign-on support.

require 'hub_sso_lib'
include HubSsoLib::Core
before_action :hubssolib_beforehand
after_action :hubssolib_afterwards
```

All internal methods have the `hubssolib_` prefix in an effort to avoid namespace collision with anything else in the including application.

#### The "before" action: `hubssolib_beforehand`

Before any action in a Hub integrated application, `hubssolib_beforehand` must be invoked. To achieve this, ensure that `application.rb` includes the method as a `before_action`, as listed above:

```ruby
before_action :hubssolib_beforehand
```

The filter is the core of the Hub protection mechanism, making sure that no action can run unless the user is logged in (unless the action is completely protected) and their account is associated with at least one of the roles required to access the action.

#### The "after" action: `hubssolib_afterwards`

After any action in a Hub integrated application, `hubssolib_afterward` must be invoked. To achieve this, ensure that `application.rb` includes the method as a `after_action`, as listed above:

```ruby
after_action :hubssolib_afterwards
```

At the time of writing the filter does nothing, but is included to allow for future expansion and avoid API changes that might force application integrators to modify their code.

#### Finding out about the current user

Most Hub integration methods are geared around making it easy to find out about a currently logged in user.

##### Is the user logged in?

Method `hubssolib_logged_in?` returns `true` if there is a Hub user presently logged in, else `false`.

##### What is the user's name?

Method `hubssolib_get_user_name` returns the display name of the currently logged in user as a string or `nil` if there is nobody logged in right now.

##### Does the user have a unique identifier?

Method `hubssolib_get_user_id` returns the Hub database ID of the currently logged in user or `nil` if there is nobody logged in right now. This numerical ID is unique but not human-readable; sometimes it is desirable to generate unique _display_ names. For example, perhaps you are integrating with an application that has its own account scheme based on unique user names shown in views (e.g. a forum) and want to create application accounts transparently to map to Hub accounts on the fly. For such purposes, call `hubssolib_unique_name`. The method returns a unique string containing the Hub user display name followed by the user ID in brackets or `nil` if nobody is logged in.

##### What is the user's e-mail address?

Method `hubssolib_get_user_address` returns the e-mail address specified by the currently logged in user when they signed up to Hub or `nil` if nobody is logged in right now. Since account confirmation in the Hub application is conducted by e-mail, the address ought to be valid unless the user created a temporary account purely for the purpose of signing up (there is no way to tell if this is the case). The e-mail address should only be used for sending solicited messages and never be displayed in views, since such addresses can be harvested for spam and as a result displaying an e-mail address without prior permission can make some account holders quite angry.

#### Checking for user permissions

Although controller actions are protected automatically by Hub, you may wish to hide things from certain users, such as links to actions they cannot perform or information that should only be seen by users with a different role set.

##### Can the user access a particular action?

Method `hubssolib_authorized?` takes two parameters:

1.  The first is an action name, specified as a string or symbol. If calling from view or helper code you need to specify this every time, but if calling from a Controller you can omit it and the current action's name (the value of `action_name`) is used instead.
2.  The second parameter is the name of the controller class, in which the action you're checking resides. If calling from that controller then again, you can omit this parameter; the class' own name (the value of `self.class`) is used instead. Otherwise, give the name; the `ClassName.hubssolib_permissions` method is used to discover the current set of permissions for the action.

By looking at the set of permissions for the controller class you specified in the second parameter for the action you specified in the first parameter, the method determines the list of permitted roles. If the currently logged in user's account has at least one of the roles associated with it, the method returns `true` to indicate that access is allowed. Otherwise, or if there is no user currently logged in, the method returns `false`.

##### Is the user's account privileged?

Although the use of roles in the lists of permissions written for controllers actually defines what each role means in practice, it's usually best to consider normal users as the least privileged and everyone else as having a more privileged access status. Sometimes you just want normal users to only access a limited amount of information or actions while anybody else, with any more privileged roles associated with their account, can do more interesting (but potentially dangerous!) things. Primarily for use in views, the `hubssolib_privileged?` method returns `true` if the currently logged in user account has any roles _other_ than just `:normal`, else `false` for `:normal` roles only, or if there is no user logged in right now.

To obtain an array of the current user's roles, call `hubssolib_get_user_roles`. This returns a `HubSsoLib:Roles` object which implements the following public methods:

*   `get_role_symbols` — returns an array of _all_ valid role symbols (e.g. `:admin` and `:normal`.
*   `get_display_name` — when passed a role symbol, returns a human-readable role name in English. If you are using an internationalised application, you'd probably just look up the key in some part of your messages file with `I18n.t` instead.
*   `get_display_names` — returns an array of human-readable role names for _all_ valid roles (see `get_display_name` above).
*   `include?` — when passed a role symbol, returns `true` if this Roles object includes that symbol, else `false`.
*   `includes?` — aliased to `include?`.
*   `validate` — integrity check — if this returns `false`, somehow an unrecognised role symbol got injected into the database for the Hub user for which this Roles object was generated, so it includes an unrecognised role. This is really a debugging function and shouldn't ever happen, but if you want to be paranoid, you could always check that any Roles object returned by Hub returns `true` when this method is called, indicating that it is valid.

As described above when talking about [`HubSsoLib::Permissions` earlier](#permissions), Hub defines roles `:normal`, `:privileged`, `:webmaster` and `:admin`. The significance attached to these depends entirely on your chosen use of them in access permissions to parts of your site.

##### Permissions for arbitrary user accounts

Although applications are normally concerned with the abilities of the _currently logged in_ user, leading to simple Hub accessor methods such as `hubssolib_authorized?`, sometimes you may need more control. For example, you may want to check action permissions of an arbitrary user as part of some administrative interface.

The `HubSsoLib::Permissions` instance you define in your controllers ([see earlier](#permissions)) is key to this. You can create an instance as discussed earlier — usually just calling your controller's own `hubssolib_permissions` class method when considering action permissions for the controller of interest is simplest. This has member method `permitted?` on this to find out if an action is allowed. Pass a Roles object in the first parameter and an action, expressed as a symbol (e.g. `:create`, `:edit`) in the second parameter. The method returns `true` if the permissions object allows the given action under the given Roles, else `false`.

In the example of "permissions for arbitrary user" you may well not have ready access to an initialised Roles object for that user, so you will probably have to build one. Use `Roles.new(...)` to create a new Roles object, passing it `true` to assign a single initial role of `:admin` or `false` to assign a single initial role of `:normal`. You can use the instance methods `add` and `delete` to add or delete roles to the object, specified as role symbols. Use `clear` to empty the object of all roles.

### Visual feedback

When a user logs in with a traditional log-in system, there's usually some message shown on the page presented when log-in is successful. This is achieved through the Hub equivalent of the Rails `flash` hash. Replace your preferred mechanism for including contents of the `flash` hash into your views (usually via one or more layout files) with an equivalent which calls Hub's flash handling code, which aggregates both current application and cross-application flash content into one.

Just using `<%= hubssolib_flash_tags -%>` in your layout(s) and/or view(s) will output merged flash data. HTML is generated consisting of `h2` tags with class names derived from the keys used in the flash tag. Each heading tag encapsulates the value for the key and is followed by an empty paragraph tag for spacing reasons on older browsers when more than one key is present, though normally there is only one. Hub itself commonly uses keys `:notice` ("green" / general information - e.g. "you are now logged in"), `:attention` ("orange" / something unusual happened - e.g. "your session timed out so you were logged out") and `:alert` ("red" / something bad happened - e.g. "incorrect password given").
