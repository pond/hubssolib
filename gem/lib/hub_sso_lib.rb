#######################################################################
# Module:  HubSsoLib                                                  #
#          (C) Hipposoft 2006-2019                                    #
#                                                                     #
# Purpose: Cross-application same domain single sign-on support.      #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 20-Oct-2006 (ADH): First version of stand-alone library,   #
#                             split from Hub application.             #
#          08-Dec-2006 (ADH): DRB URI, path prefix and random file    #
#                             path come from environment variables.   #
#          09-Mar-2011 (ADH): Updated for Hub on Rails 2.3.11 along   #
#                             with several important bug fixes.       #
#          01-May-2019 (ADH): Updated for Ruby 2.5.x.                 #
#######################################################################

module HubSsoLib

  require 'drb'
  require 'securerandom'

  # DRb connection
  HUB_CONNECTION_URI = ENV['HUB_CONNECTION_URI'] || 'drbunix:' + File.join( ENV['HOME'] || '/', '/.hub_drb')

  unless HUB_CONNECTION_URI.downcase.start_with?('drbunix:')
    puts
    puts '*' * 80
    puts "You *must* use a 'drbunix:' scheme for HUB_CONNECTION_URI (#{ HUB_CONNECTION_URI.inspect } is invalid)"
    puts '*' * 80
    puts

    raise 'Exiting'
  end

  # Location of Hub application root.
  HUB_PATH_PREFIX = ENV['HUB_PATH_PREFIX'] || ''

  # Time limit, *in seconds*, for the account inactivity timeout.
  # If a user performs no Hub actions during this time they will
  # be automatically logged out upon their next action.
  HUB_IDLE_TIME_LIMIT = 4 * 60 * 60

  # Shared cookie name.
  HUB_COOKIE_NAME = :hubapp_shared_id

  # Principally for #hubssolib_account_link.
  HUB_LOGIN_INDICATOR_COOKIE       = :hubapp_shared_id_alive
  HUB_LOGIN_INDICATOR_COOKIE_VALUE = 'Y'

  # Bypass SSL, for testing purposes? Rails 'production' mode will
  # insist on SSL otherwise. Development & test environments do not,
  # so do not need this variable setting.
  HUB_BYPASS_SSL = ( ENV['HUB_BYPASS_SSL'] == "true" )

  # Thread safety.
  HUB_MUTEX = Mutex.new

  #######################################################################
  # Class:   Serialiser                                                 #
  #          (C) Hipposoft 2020                                         #
  #                                                                     #
  # Purpose: Simple object serialiser/deserialiser.                     #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 18-Apr-2002 (ADH): First version.                          #
  #######################################################################

  # Simple object serialiser and deserialiser using Marshal and Base64.
  #
  class Serialiser
    require 'base64'

    def self.serialise_object(object)
      Base64.strict_encode64(Marshal.dump(object))
    end

    def self.deserialise_object(data)
      Marshal.load(Base64.strict_decode64(data)) rescue nil
    end
  end # Serialiser class

  #######################################################################
  # Class:   Roles                                                      #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: Shared methods for handling user account roles.            #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 17-Oct-2006 (ADH): Adapted from Clubhouse.                 #
  #          20-Oct-2006 (ADH): Integrated into HubSsoLib.              #
  #######################################################################

  class Roles

    # Association of symbolic role names to display names, in no
    # particular order.
    #
    ROLES = {
              :admin      => 'Administrator',
              :webmaster  => 'Webmaster',
              :privileged => 'Advanced user',
              :normal     => 'Normal user'
            }

    ADMIN  = :admin
    NORMAL = :normal

    # Return the display name of a given role symbol. Class method.
    #
    def self.get_display_name(symbol)
      ROLES[symbol]
    end

    # Return all display names in an array. Class method.

    def self.get_display_names
      ROLES.values
    end

    # Return an array of known role symbols. They can be used with
    # methods like get_display_name. Class method.

    def self.get_role_symbols
      ROLES.keys
    end

    # Initialize a new Roles object. Pass 'true' if this is for
    # an admin user account, else 'false'. Default is 'false'. Note
    # that further down in this file, the String, Symbol and Array
    # classes are extended with to_authenticated_roles methods, which
    # provide other ways of creating Roles objects.
    #
    def initialize(admin = false)
      if (admin)
        @role_array = [ ADMIN ]
      else
        @role_array = [ NORMAL ]
      end
    end

    # Adds a role, supplied as a string or symbol, to the internal list.
    # A non-nil return indicates that the role was already present.
    #
    def add(role)
      @role_array.push(role.to_s.intern).uniq!
    end

    # Deletes a role, supplied as a string or symbol, from the internal
    # list. A nil return indicates that the role was not in the list.
    #
    def delete(role)
      @role_array.delete(role.to_s.intern)
    end

    # Delete all roles from the internal list.
    #
    def clear
      @role_array.clear
    end

    # Return a copy of the internal roles list as a string.
    #
    def to_s
      return @role_array.join(',')
    end

    # Return a copy of the internal roles list as an array.
    #
    def to_a
      return @role_array.dup
    end

    # Return a copy of the intenal roles list as a human readable string.
    #
    def to_human_s
      human_names = []

      @role_array.each do |role|
        human_names.push(HubSsoLib::Roles.get_display_name(role))
      end

      if (human_names.length == 0)
        return ''
      elsif (human_names.length == 1)
        return human_names[0]
      else
        return human_names[0..-2].join(', ') + ' and ' + human_names.last
      end
    end

    # Do nothing - this is just useful for polymorphic code, where a function
    # can take a String, Array, Symbol or Roles object and make the
    # same method call to return a Roles object in return.
    #
    def to_authenticated_roles
      return self
    end

    # Does the internal list of roles include the supplied role or roles?
    # The roles can be given as an array of individual role symbols or
    # equivalent strings, or as a single symbol or single equivalent
    # symbol, or as a string containing equivalents of role symbols in a
    # comma-separated list (no white space or other spurious characters).
    # Returns 'true' if the internal list of roles includes at least one
    # of the supplied roles, else 'false'.
    #
    def include?(roles)
      return false if roles.nil?

      # Ensure we've an array of roles, one way or another
      roles = roles.to_s       if roles.class == Symbol
      roles = roles.split(',') if roles.class == String

      roles.each do |role|
        return true if @role_array.include?(role.to_s.intern)
      end

      return false
    end

    # Synonym for 'include?'.
    #
    alias includes? include?

    # Validate the list of roles. Validation means ensuring that all
    # roles in this object are found in the internal ROLES hash. Returns
    # true if the roles validate or false if unknown roles are found.
    #
    def validate
      return false if @role_array.empty?

      @role_array.each do |role|
        return false unless ROLES[role]
      end

      return true
    end

  end # Roles class

  #######################################################################
  # Class:   Permissions                                                #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: Methods to help, in conjunction with Roles, determine the  #
  #          access permissions a particular user is granted.           #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 17-Oct-2006 (ADH): Adapted from Clubhouse.                 #
  #          20-Oct-2006 (ADH): Integrated into HubSsoLib.              #
  #######################################################################

  class Permissions

    # Initialize a permissions object. The map is a hash which maps action
    # names, expressed as symbols, to roles, expressed as individual symbols,
    # equivalent strings, or arrays of multiple strings or symbols. Use 'nil'
    # to indicate permission for the general public - no login required - or
    # simply omit the action (unlisted actions are permitted).
    #
    # Example mapping for a generic controller:
    #
    # {
    #   :new     => [ :admin, :webmaster, :privileged, :normal ],
    #   :create  => [ :admin, :webmaster, :privileged, :normal ],
    #   :edit    => [ :admin, :webmaster, :privileged, :normal ],
    #   :update  => [ :admin, :webmaster, :privileged, :normal ],
    #   :delete  => [ :admin, :webmaster, :privileged ],
    #   :list    => nil,
    #   :show    => nil
    # }
    #
    def initialize(pmap)
      @permissions = pmap
    end

    # Does the given Roles object grant permission for the given action,
    # expressed as a string or symbol? Returns 'true' if so, else 'false'.
    #
    # If a role is given as some other type, an attempt is made to convert
    # it to a Roles object internally (so you could pass a role symbol,
    # string, array of symbols or strings, or comma-separated string).
    #
    # Passing an empty roles string will tell you whether or not the
    # action requires login. Only actions not in the permissions list or
    # those with a 'nil' list of roles will generate a result 'true',
    # since any other actions will require your empty roles string to
    # include at least one role (which it obviously doesn't).
    #
    def permitted?(roles, action)
      action = action.to_s.intern
      roles  = roles.to_authenticated_roles

      return true unless @permissions.include?(action)
      return true if @permissions[action].nil?
      return roles.include?(@permissions[action])
    end
  end # Permissions class

  #######################################################################
  # Class:   User                                                       #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: A representation of the Hub application's User Model in    #
  #          terms of a simple set of properties, so that applications  #
  #          don't need User access to understand user attributes.      #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 21-Oct-2006 (ADH): Created.                                #
  #######################################################################

  class User

    # This *must not* be 'undumped', since it gets passed from clients
    # back to the persistent DRb server process. A client thread may
    # disappear and be recreated by the web server at any time; if the
    # user object is undumpable, then the DRb server has to *call back
    # to the client* (in DRb, clients are also servers...!) to find out
    # about the object. Trouble is, if the client thread has been
    # recreated, the server will be trying to access to stale objects
    # that only exist if the garbage collector hasn't got to them yet.

    attr_accessor :user_salt
    attr_accessor :user_roles
    attr_accessor :user_updated_at
    attr_accessor :user_activated_at
    attr_accessor :user_real_name
    attr_accessor :user_crypted_password
    attr_accessor :user_remember_token_expires_at
    attr_accessor :user_activation_code
    attr_accessor :user_member_id
    attr_accessor :user_id
    attr_accessor :user_password_reset_code
    attr_accessor :user_remember_token
    attr_accessor :user_email
    attr_accessor :user_created_at
    attr_accessor :user_password_reset_code_expires_at

    def initialize
      @user_salt = nil
      @user_roles = nil
      @user_updated_at = nil
      @user_activated_at = nil
      @user_real_name = nil
      @user_crypted_password = nil
      @user_remember_token_expires_at = nil
      @user_activation_code = nil
      @user_member_id = nil
      @user_id = nil
      @user_password_reset_code = nil
      @user_remember_token = nil
      @user_email = nil
      @user_created_at = nil
      @user_password_reset_code_expires_at = nil
    end
  end # User class

  #######################################################################
  # Class:   Session                                                    #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: Session support object, used to store session metadata in  #
  #          an insecure cross-application cookie.                      #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 22-Oct-2006 (ADH): Created.                                #
  #######################################################################

  class Session

    # Unlike a User, this *is* undumpable since it only gets passed from
    # server to client. The server's always here to service requests
    # from the client and used sessions are never garbage collected
    # since the DRb server's front object, a SessionFactory, keeps them
    # in a hash held within an instance variable.

    include DRb::DRbUndumped

    attr_accessor :session_last_used
    attr_accessor :session_return_to
    attr_accessor :session_flash
    attr_accessor :session_user
    attr_accessor :session_key_rotation
    attr_accessor :session_ip

    def initialize
      @session_last_used    = Time.now.utc
      @session_return_to    = nil
      @session_flash        = {}
      @session_user         = HubSsoLib::User.new
      @session_key_rotation = nil
      @session_ip           = nil
    end
  end # Session class

  #######################################################################
  # Class:   SessionFactory                                             #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: Build Session objects for DRb server clients. Maintains a  #
  #          hash of Session objects.                                   #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 26-Oct-2006 (ADH): Created.                                #
  #######################################################################

  class SessionFactory
    def initialize
      @hub_be_quiet = ! ENV['HUB_QUIET_SERVER'].nil?
      @hub_sessions = {}

      puts "Session factory: Awaken" unless @hub_be_quiet
    end

    # Get a session using a given key (a UUID). Generates a new session if
    # the key is unrecognised or if the IP address given mismatches the one
    # recorded in existing session data.
    #
    # Whether new or pre-existing, the returned session will have changed key
    # as a result of being read; check the #session_key_rotation property to
    # find out the new key. If you fail to do this, you'll lose access to the
    # session data as you won't know which key it lies under.
    #
    # The returned object is proxied via DRb - it is shared between processes.
    #
    # +key+::       Session key; lazy-initialises a new session under this key
    #               if none is found, then immediately rotates it.
    #
    # +remote_ip+:: Request's remote IP address. If there is an existing
    #               session which matches this, it's returned. If there is an
    #               existing session but the IP mismatches, it's treated as
    #               invalid and discarded.
    #
    def get_hub_session_proxy(key, remote_ip)
      hub_session = @hub_sessions[key]
      message     = hub_session.nil? ? 'Created' : 'Retrieving'
      new_key     = SecureRandom.uuid

      unless @hub_be_quiet
        puts "#{ message } session for key #{ key } and rotating to #{ new_key }"
      end

      unless hub_session.nil? || hub_session.session_ip == remote_ip
        unless @hub_be_quiet
          puts "WARNING: IP address changed from #{ hub_session.session_ip } to #{ remote_ip } -> discarding session"
        end

        hub_session = nil
      end

      if hub_session.nil?
        hub_session            = HubSsoLib::Session.new
        hub_session.session_ip = remote_ip
      end

      @hub_sessions.delete(key)
      @hub_sessions[new_key] = hub_session

      hub_session.session_key_rotation = new_key
      return hub_session
    end

    def enumerate_hub_sessions()
      @hub_sessions
    end
  end

  #######################################################################
  # Module:  Server                                                     #
  #          (C) Hipposoft 2006                                         #
  #                                                                     #
  # Purpose: DRb server to provide shared data across applications.     #
  #          Thanks to RubyPanther, rubyonrails IRC, for suggesting     #
  #          this after a cookie-based scheme failed.                   #
  #                                                                     #
  #          Include the module then call hubssolib_launch_server. The  #
  #          call will not return as the server runs indefinitely.      #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 26-Oct-2006 (ADH): Created.                                #
  #######################################################################

  module Server
    def hubssolib_launch_server
      puts "Server: Starting at #{ HUB_CONNECTION_URI }" unless ENV['HUB_QUIET_SERVER'].nil?

      @@hub_session_factory = HubSsoLib::SessionFactory.new
      DRb.start_service(HUB_CONNECTION_URI, @@hub_session_factory, { :safe_level => 1 })
      DRb.thread.join
    end
  end # Server module

  #######################################################################
  # Module:  Core                                                       #
  #          Various authors                                            #
  #                                                                     #
  # Purpose: The barely recognisable core of acts_as_authenticated's    #
  #          AuthenticatedSystem module, modified to work with the      #
  #          other parts of HubSsoLib. You should include this module   #
  #          to use its facilities.                                     #
  #                                                                     #
  # Author:  Various; adaptation by A.D.Hodgkinson                      #
  #                                                                     #
  # History: 20-Oct-2006 (ADH): Integrated into HubSsoLib.              #
  #######################################################################

  module Core

    # Returns true or false if the user is logged in.
    #
    # Preloads @hubssolib_current_user with user data if logged in.
    #
    def hubssolib_logged_in?
      !!self.hubssolib_current_user
    end

    # Returns markup for a link that leads to Hub's conditional login endpoint,
    # inline-styled as a red "Log in" or green "Account" button. This can be
    # used in page templates to avoid needing any additional images or other
    # such resources and using pure HTML + CSS for the login indication.
    #
    # JavaScript is used so that e.g. "back" button fully-cached displays by a
    # browser will get updated with the correct login state, where needed (so
    # long as the 'pageshow' event is supported). NOSCRIPT browsers use the old
    # no-cache image fallback, which is much less efficient, but works.
    #
    def hubssolib_account_link
      logged_in        = self.hubssolib_logged_in?()

      ui_href          = "#{HUB_PATH_PREFIX}/account/login_conditional"
      noscript_img_src = "#{HUB_PATH_PREFIX}/account/login_indication.png"
      noscript_img_tag = helpers.image_tag(noscript_img_src, size: '90x22', border: '0', alt: 'Log in or out')

      logged_in_link   = helpers.link_to('Account',        ui_href, id: 'hubssolib_logged_in_link')
      logged_out_link  = helpers.link_to('Log in',         ui_href, id: 'hubssolib_logged_out_link')
      noscript_link    = helpers.link_to(noscript_img_tag, ui_href, id: 'hubssolib_login_noscript')

      # Yes, it's ugly, but yes, it works and it's a lot better for the server
      # to avoid the repeated image fetches. It probably works out as overall
      # more efficient for clients too - despite all the JS etc. work, there's
      # no network fetch overhead or image rendering. On mobile in particular,
      # the JS solution is likely to use less battery power.
      #
      safe_markup = <<~HTML
        <div id="hubssolib_login_indication">
          <noscript>
            #{noscript_link}
          </noscript>
        </div>
        <script type="text/javascript">
          const logged_in_html  = "#{helpers.j(logged_in_link)}";
          const logged_out_html = "#{helpers.j(logged_out_link)}";
          const container       = document.getElementById('hubssolib_login_indication')

          #{
            # No '?.' support in NetSurf's JS engine, so can't do the match
            # and pop in a single line via "?.pop() || ''".
          }
          function hubSsoLibLoginStateWriteLink() {
            const regexp = '#{helpers.j(HUB_LOGIN_INDICATOR_COOKIE)}\\s*=\\s*([^;]+)';
            const match  = document.cookie.match(regexp);
            const flag   = (match ? match.pop() : null) || '';

            if (flag === '#{HUB_LOGIN_INDICATOR_COOKIE_VALUE}') {
              container.innerHTML = logged_in_html;
            } else {
              container.innerHTML = logged_out_html;
            }
          }
          #{
            # Immediate update, plus on-load update - including fully cached
            # loads in the browser when the "Back" button is used. No stale
            # login indications should thus arise from cached data.
          }
          hubSsoLibLoginStateWriteLink();
          window.addEventListener('load',     hubSsoLibLoginStateWriteLink);
          window.addEventListener('pageshow', hubSsoLibLoginStateWriteLink);
        </script>
      HTML

      return safe_markup.html_safe()
    end

    # Check if the user is authorized to perform the current action. If calling
    # from a helper, pass the action name and class name; otherwise by default,
    # the current action name and 'self.class' will be used.
    #
    # Override this method in your controllers if you want to restrict access
    # to a different set of actions. Presently, the current user's roles are
    # compared against the caller's permissions hash and the action name.
    #
    def hubssolib_authorized?(action = action_name, classname = self.class)

      # Classes with no permissions object always authorise everything.
      # Otherwise, ask the permissions object for its opinion.

      if (classname.respond_to? :hubssolib_permissions)
        return classname.hubssolib_permissions.permitted?(hubssolib_get_user_roles, action)
      else
        return true
      end
    end

    # Is the current user privileged? Anything other than normal user
    # privileges will suffice. Can be called if not logged in. Returns
    # 'false' for logged out or normal user privileges only, else 'true'.
    #
    def hubssolib_privileged?
      return false unless hubssolib_logged_in?

      pnormal = HubSsoLib::Roles.new(false).to_s
      puser   = hubssolib_get_user_roles().to_s

      return (puser && !puser.empty? && puser != pnormal)
    end

    # Log out the user. Very few applications should ever need to call this,
    # though Hub certainly does and it gets used internally too.
    #
    def hubssolib_log_out
      # Causes the "hubssolib_current_[foo]=" methods to run, which
      # deal with everything else.
      self.hubssolib_current_user = nil
      @hubssolib_current_session_proxy = nil
    end

    # Accesses the current session from the cookie. Creates a new session
    # object if need be, but can return +nil+ if e.g. attempting to access
    # session cookie data without SSL.
    #
    def hubssolib_current_session
      @hubssolib_current_session_proxy ||= hubssolib_get_session_proxy()
    end

    # Accesses the current user, via the DRb server if necessary.
    #
    def hubssolib_current_user
      hub_session = self.hubssolib_current_session
      user        = hub_session.nil? ? nil : hub_session.session_user

      if (user && user.user_id)
        return user
      else
        return nil
      end
    end

    # Store the given user data in the cookie
    #
    def hubssolib_current_user=(user)
      hub_session = self.hubssolib_current_session
      hub_session.session_user = user unless hub_session.nil?
    end

    # Public read-only accessor methods for common user activities:
    # return the current user's roles as a Roles object, or nil if
    # there's no user.
    #
    def hubssolib_get_user_roles
      user = self.hubssolib_current_user
      user ? user.user_roles.to_authenticated_roles : nil
    end

    # Public read-only accessor methods for common user activities:
    # return the current user's name as a string, or nil if there's
    # no user. See also hubssolib_unique_name.
    #
    def hubssolib_get_user_name
      user = self.hubssolib_current_user
      user ? user.user_real_name : nil
    end

    # Public read-only accessor methods for common user activities:
    # return the Hub database ID of the current user account, or
    # nil if there's no user. See also hubssolib_unique_name.
    #
    def hubssolib_get_user_id
      user = self.hubssolib_current_user
      user ? user.user_id : nil
    end

    # Public read-only accessor methods for common user activities:
    # return the current user's e-mail address, or nil if there's
    # no user.
    #
    def hubssolib_get_user_address
      user = self.hubssolib_current_user
      user ? user.user_email : nil
    end

    # Return a human-readable unique ID for a user. We don't want to
    # have e-mail addresses all over the place, but don't want to rely
    # on real names as unique - they aren't. Instead, produce a
    # composite of the user's account database ID (which must be
    # unique by definition) and their real name. See also
    # hubssolib_get_name.
    #
    def hubssolib_unique_name
      user = hubssolib_current_user
      user ? "#{user.user_real_name} (#{user.user_id})" : 'Anonymous'
    end

    # Main filter method to implement HubSsoLib permissions management,
    # session expiry and so-on. Call from controllers only, always as a
    # before_fitler.
    #
    def hubssolib_beforehand

      # Does this action require a logged in user?
      #
      if (self.class.respond_to? :hubssolib_permissions)
        login_is_required = !self.class.hubssolib_permissions.permitted?('', action_name)
      else
        login_is_required = false
      end

      # If we require login but we're logged out, redirect to Hub login.
      # NOTE EARLY EXIT
      #
      logged_in = hubssolib_logged_in?

      if logged_in == false
        cookies.delete(HUB_LOGIN_INDICATOR_COOKIE, domain: :all, path: '/')

        if login_is_required
          hubssolib_store_location
          return hubssolib_must_login
        else
          return true
        end
      end

      # Definitely logged in.
      #
      cookies[HUB_LOGIN_INDICATOR_COOKIE] = {
        value:    HUB_LOGIN_INDICATOR_COOKIE_VALUE,
        path:     '/',
        domain:   :all,
        expires:  1.year, # I.e. *not* session-scope
        secure:   ! hub_bypass_ssl?,
        httponly: false
      }

      # So we reach here knowing we're logged in, but the action may or
      # may not require authorisation.

      if (login_is_required)

        # Login *is* required for this action. If the session expires,
        # redirect to Hub's login page via its expiry action. Otherwise
        # check authorisation and allow action processing to continue
        # if OK, else indicate that access is denied.

        if (hubssolib_session_expired?)
          hubssolib_store_location
          hubssolib_log_out
          hubssolib_set_flash(:attention, 'Sorry, your session timed out; you need to log in again to continue.')

          # We mean this: redirect_to :controller => 'account', :action => 'login'
          # ...except for the Hub, rather than the current application (whatever
          # it may be).
          redirect_to HUB_PATH_PREFIX + '/account/login'
        else
          hubssolib_set_last_used(Time.now.utc)
          return hubssolib_authorized? ? true : hubssolib_access_denied
        end

      else

        # We have to update session expiry even for actions that don't
        # need us to be logged in, since we *are* logged in and need to
        # maintain that state. If, though, the session expires, we just
        # quietly log out and let action processing carry on.

        if (hubssolib_session_expired?)
          hubssolib_log_out
          hubssolib_set_flash(:attention, 'Your session timed out, so you are no longer logged in.')
        else
          hubssolib_set_last_used(Time.now.utc)
        end

        return true # true -> let action processing continue

      end
    end

    # Main after_filter method to tidy up after running state changes.
    #
    def hubssolib_afterwards
      begin
        DRb.current_server
        DRb.stop_service()
      rescue DRb::DRbServerNotFound
        # Nothing to do; no service is running.
      end
    end

    # Store the URI of the current request in the session, or store the
    # optional supplied specific URI.
    #
    # We can return to this location by calling #redirect_back_or_default.
    #
    def hubssolib_store_location(uri_str = request.url)

      if (uri_str && !uri_str.empty?)
        uri_str = hubssolib_promote_uri_to_ssl(uri_str, request.host) unless request.ssl?
        hubssolib_set_return_to(uri_str)
      else
        hubssolib_set_return_to(nil)
      end

    end

    # Redirect to the URI stored by the most recent store_location call or
    # to the passed default.
    def hubssolib_redirect_back_or_default(default)
      url = hubssolib_get_return_to
      hubssolib_set_return_to(nil)

      redirect_to(url || default)
    end

    # Take a URI and pass an optional host parameter. Decomposes the URI,
    # sets the host you provide (or leaves it alone if you omit the
    # parameter), then forces the scheme to 'https'. Returns the result
    # as a flat string.

    def hubssolib_promote_uri_to_ssl(uri_str, host = nil)
      uri = URI.parse(uri_str)
      uri.host = host if host
      uri.scheme = hub_bypass_ssl? ? 'http' : 'https'
      return uri.to_s
    end

    # Ensure the current request is carried out over HTTPS by redirecting
    # back to the current URL with the HTTPS protocol if it isn't. Returns
    # 'true' if not redirected (already HTTPS), else 'false'.
    #
    def hubssolib_ensure_https
      if request.ssl? || hub_bypass_ssl?
        return true
      else
        # This isn't reliable: redirect_to({ :protocol => 'https://' })
        redirect_to( hubssolib_promote_uri_to_ssl( request.request_uri, request.host ) )
        return false
      end
    end

    # Public methods to set some data that would normally go in @session,
    # but can't because it needs to be accessed across applications. It is
    # put in an insecure support cookie instead. There are some related
    # private methods for things like session expiry too.
    #
    def hubssolib_get_flash()
      f = self.hubssolib_current_session ? self.hubssolib_current_session.session_flash : nil
      return f || {}
    end

    def hubssolib_set_flash(symbol, message)
      return unless self.hubssolib_current_session
      f = hubssolib_get_flash
      f[symbol.to_s] = message
      self.hubssolib_current_session.session_flash = f
    end

    def hubssolib_clear_flash
      return unless self.hubssolib_current_session
      self.hubssolib_current_session.session_flash = {}
    end

    # Return flash data for known keys, then all remaining keys, from both
    # the cross-application and standard standard flash hashes. The returned
    # Hash is of the form:
    #
    #   { 'hub' => ...data..., 'standard' => ...data... }
    #
    # ...where "...data..." is itself a Hash of flash keys yielding flash
    # values. This allows both the Hub and standard flashes to have values
    # inside them under the same key. All keys are strings.
    #
    def hubssolib_flash_data

      # These known key values are used to guarantee an order in the output
      # for cases where multiple messages are defined.
      #
      compiled_data = { 'hub' => {}, 'standard' => {} }
      ordered_keys  = [
        'notice',
        'attention',
        'alert'
      ]

      # Get an array of keys for the Hub flash with the ordered key items
      # first and store data from that flash; same again for standard.

      hash = hubssolib_get_flash()
      keys = ordered_keys | hash.keys

      keys.each do | key |
        compiled_data['hub'][key] = hash[key] if hash.key?(key)
      end

      if defined?( flash )
        hash = flash.to_h()
        keys = ordered_keys | hash.keys

        keys.each do | key |
          compiled_data['standard'][key] = hash[key] if hash.key?(key)
        end
      end

      hubssolib_clear_flash()
      flash.discard()

      return compiled_data
    end

    # Retrieve the message of an exception stored as an object in the given
    # string.
    #
    def hubssolib_get_exception_message(id_data)
      hubssolib_get_exception_data(CGI::unescape(id_data))
    end

    # Inclusion hook to make various methods available as ActionView
    # helper methods.
    #
    def self.included(base)
      base.send :helper_method,
                :hubssolib_current_user,
                :hubssolib_unique_name,
                :hubssolib_logged_in?,
                :hubssolib_account_link,
                :hubssolib_authorized?,
                :hubssolib_privileged?,
                :hubssolib_flash_data
    rescue
      # We're not always included in controllers...
      nil
    end

  private

    # Establish a single DRb factory connection.
    #
    def hubssolib_factory
      HUB_MUTEX.synchronize do
        begin
          DRb.current_server
        rescue DRb::DRbServerNotFound
          DRb.start_service()
        end

        @factory ||= DRbObject.new_with_uri(HUB_CONNECTION_URI)
      end

      return @factory
    end

    # Helper that decides if we should insist on SSL (or not).
    #
    def hub_bypass_ssl?
      HUB_BYPASS_SSL || ! Rails.env.production?
    end

    # Indicate that the user must log in to complete their request.
    # Returns false to enable a before_filter to return through this
    # method while ensuring that the previous action processing is
    # halted (since the overall return value is therefore 'false').
    #
    def hubssolib_must_login
      # If HTTP, redirect to the same place, but HTTPS. Then we can store the
      # flash and return-to in the session data. We'll have the same set of
      # before-filter operations running and they'll find out we're either
      # authorised after all, or come back to this very function, which will
      # now be happily running from an HTTPS connection and will go on to set
      # the flash and redirect to the login page.

      if hubssolib_ensure_https
        hubssolib_set_flash(:alert, 'You must log in before you can continue.')
        redirect_to HUB_PATH_PREFIX + '/account/login'
      end

      return false
    end

    # Indicate access is denied for a given logged in user's request.
    # Returns false to enable a before_filter to return through this
    # method while ensuring that the previous action processing is
    # halted (since the overall return value is therefore 'false').
    #
    def hubssolib_access_denied
      # See hubsso_must_login for the reason behind the following call.

      if hubssolib_ensure_https
        hubssolib_set_flash(:alert, 'You do not have permission to carry out that action on this site.')
        redirect_to HUB_PATH_PREFIX + '/'
      end

      return false
    end

    # Check conditions for session expiry. Returns 'true' if session's
    # last_used date indicates expiry, else 'false'.
    #
    def hubssolib_session_expired?

      # 23-Oct-2006 (ADH):
      #
      # An exception, which is also a security hole of sorts. POST requests
      # cannot be redirected because HTTP doesn't have that concept. If a user
      # is editing a Wiki page, say, then goes away, comes back later and now
      # finishes their edits, their session may have timed out. They submit
      # the page but it's by POST so their submission details are lost. If they
      # are lucky their browser might remember the form contents if they go
      # back but not all do and not all users would think of doing that.
      #
      # To work around this, don't enforce a timeout for POST requests. Should
      # a user on a public computer not log out, then a hacker arrive *after*
      # the session expiry time (if they arrive before it expires then the
      # except for POSTs is irrelevant), they could recover the session by
      # constructing a POST request. It's a convoluted path, requires a user to
      # have not logged out anyway, and the Hub isn't intended for Fort Knox.
      # At the time of writing the trade-off of usability vs security is
      # considered acceptable, though who knows, the view may change in future.

      last_used = hubssolib_get_last_used
      (request.method != :post && last_used && Time.now.utc - last_used > HUB_IDLE_TIME_LIMIT)
    end

    def hubssolib_get_session_proxy
      # If we're not using SSL, forget it
      return nil unless request.ssl? || hub_bypass_ssl?

      key         = cookies[HUB_COOKIE_NAME] || SecureRandom.uuid
      hub_session = hubssolib_factory().get_hub_session_proxy(key, request.remote_ip)
      key         = hub_session.session_key_rotation unless hub_session.nil?

      cookies[HUB_COOKIE_NAME] = {
        value:    key,
        path:     '/',
        domain:   :all,
        secure:   ! hub_bypass_ssl?,
        httponly: true
      }

      return hub_session

    rescue Exception => e

      # At this point there tends to be no Session data, so we're
      # going to have to encode the exception data into the URI...
      # It must be escaped twice, as many servers treat "%2F" in a
      # URI as a "/" and Apache may flat refuse to serve the page,
      # raising a 404 error unless "AllowEncodedSlashes on" is
      # specified in its configuration.

      suffix   = '/' + CGI::escape(CGI::escape(hubssolib_set_exception_data(e)))
      new_path = HUB_PATH_PREFIX + '/tasks/service'
      redirect_to(new_path + suffix) unless request.path.include?(new_path)

      return nil
    end

    def hubssolib_set_session_data(session)
      # Nothing to do presently - DRb handles everything
    end

    # Return an array of Hub User objects representing users based
    # on a list of known sessions returned by the DRb server. Note
    # that if an application exposes this method to a view, it is
    # up to the application to ensure sufficient access permission
    # protection for that view according to the webmaster's choice
    # of site security level. Generally, normal users should not
    # be allowed access.
    #
    def hubssolib_enumerate_users
      sessions = hubssolib_factory().enumerate_hub_sessions()
      users    = []

      sessions.each do |key, value|
        user = value.session_user
        users.push(user) if (user && user.respond_to?(:user_id) && user.user_id)
      end

      return users

    rescue Exception => e

      # At this point there tends to be no Session data, so we're
      # going to have to encode the exception data into the URI...
      # See earlier for double-escaping rationale.

      suffix   = '/' + CGI::escape(CGI::escape(hubssolib_set_exception_data(e)))
      new_path = HUB_PATH_PREFIX + '/tasks/service'
      redirect_to new_path + suffix unless request.path.include?(new_path)
      return nil
    end

    # Encode exception data into a string suitable for using in a URL
    # if CGI escaped first. Pass the exception object; stores only the
    # message.
    #
    def hubssolib_set_exception_data(e)
      if Rails.env.development?
        backtrace = e.backtrace.join( ", " )
        HubSsoLib::Serialiser.serialise_object("#{ e.message }: #{ backtrace }"[0..511])
      else
        HubSsoLib::Serialiser.serialise_object(e.message[0..511])
      end
    end

    # Decode exception data encoded with hubssolib_set_exception_data.
    # Returns the originally stored message string or 'nil' if there
    # are any decoding problems. Pass the encoded data.
    #
    def hubssolib_get_exception_data(data)
      HubSsoLib::Serialiser.deserialise_object(data)
    end

    # Various accessors that ultimately run through the DRb server if
    # the session data is available, else return default values.

    def hubssolib_get_last_used
      session = self.hubssolib_current_session
      session ? session.session_last_used : Time.now.utc
    end

    def hubssolib_set_last_used(time)
      return unless self.hubssolib_current_session
      self.hubssolib_current_session.session_last_used = time
    end

    def hubssolib_get_return_to
      session = self.hubssolib_current_session
      session ? session.session_return_to : nil
    end

    def hubssolib_set_return_to(uri)
      return unless self.hubssolib_current_session
      self.hubssolib_current_session.session_return_to = uri
    end

  end # Core module
end # HubSsoLib module

#######################################################################
# Classes: Standard class extensions for HubSsoLib Roles operations.  #
#          (C) Hipposoft 2006                                         #
#                                                                     #
# Purpose: Extensions to standard classes to support HubSsoLib.       #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 20-Oct-2006 (ADH): Integrated into HubSsoLib.              #
#######################################################################

# Method to return a Roles object created from the
# contents of the String the method is invoked upon. The
# string may contain a single role or a comma-separated list
# with no white space.
#
class String
  def to_authenticated_roles
    roles = HubSsoLib::Roles.new
    array = self.split(',')

    roles.clear
    array.each { |role| roles.add(role) }

    return roles
  end
end # String class

# Method to return a Roles object created from the
# contents of the Symbol the method is invoked upon.
#
class Symbol
  def to_authenticated_roles
    return self.to_s.to_authenticated_roles
  end
end # Symbol class

# Method to return a Roles object created from the
# contents of the Array the method is invoked upon. The array
# contents will be flattened. After that, each entry must be
# a single role symbol or string equivalent. Comma-separated
# lists are not currently allowed (improvements to the roles
# class could easily give this, but the bloat isn't needed).
#
class Array
  def to_authenticated_roles
    roles = HubSsoLib::Roles.new
    roles.clear

    self.flatten.each { |entry| roles.add(entry.to_s) }

    return roles
  end
end # Array class
