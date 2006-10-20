#######################################################################
# Module:  HubSsoLib                                                  #
#          By Hipposoft, 2006                                         #
#                                                                     #
# Purpose: Cross-application same domain single sign-on support.      #
#                                                                     #
# Author:  A.D.Hodgkinson                                             #
#                                                                     #
# History: 20-Oct-2006 (ADH): First version of stand-alone library,   #
#                             split from Hub application.             #
#######################################################################

module HubSsoLib

  #######################################################################
  # Class:   Crypto                                                     #
  #          By Hipposoft, 2006                                         #
  #                                                                     #
  # Purpose: Encryption and decryption utilities.                       #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 28-Aug-2006 (ADH): First version.                          #
  #          20-Oct-2006 (ADH): Integrated into HubSsoLib, renamed to   #
  #                             'Crypto' from 'HubSsoCrypto'.           #
  #######################################################################

  # Encryption and decryption utility object. Once instantiated with the
  # filename of a file that holds at least 1K of pseudo-random data, a
  # HubSsoLib::Crypto object is used to encrypt and decrypt data with the
  # AES-256-CBC cipher. A single passphrase is used for both operations.
  # A SHA-256 hash of that passphrase is used as the encryption key.
  #
  # CBC operation requires an initialization vector for the first block of
  # data during encryption and decryption. The file of random data is used
  # for this in conjunction with the passphrase used to generate the key. By
  # so doing, the initialization vector is not revealed to third parties,
  # even though the source code of the object is available. The weakness is
  # that for a given passphrase and random data pool the same initialization
  # vector will always be generated - indeed, this is relied upon, to allow
  # callers themselves to only have to remember the passphrase. See private
  # method obtain_iv() for more details.
  #
  class Crypto

    require 'openssl'
    require 'digest/sha2'
    require 'digest/md5'

    # Initialize the HubSsoLib::Crypto object. Must pass a pathname to a file
    # of effectively random data of at least 1K in length. If the data is
    # larger than 16K in size, everything after the first 16K will be
    # ignored. The data is cached internally when the object starts.
    #
    def initialize(rnd_file)
      # Check the file size and find out how much data to read - at least 1K,
      # no more than 16K. Store the size in @rnd_size and read the data into
      # @rnd_data, both for use later.

      @rnd_size = File.size(rnd_file)
      @rnd_size = 16384 if (@rnd_size > 16384)

      if @rnd_size < 1024
        raise "HubSsoLib::Crypto objects need at least 1024 bytes of random data - file '#{rnd_file}' is too small"
      else
        @rnd_data = File.open(rnd_file, 'rb').read(@rnd_size)
      end
    end

    # Encrypt the given data with the AES-256-CBC algorithm using the
    # given passphrase. Returns the encrypted result in a string.
    # Distantly based upon:
    #
    #   http://www.bigbold.com/snippets/posts/show/576
    #
    def encrypt(data, passphrase)
      cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      cipher.encrypt

      cipher.key = Digest::SHA256.digest(passphrase)
      cipher.iv  = obtain_iv(passphrase)

      encrypted  = cipher.update(data)
      encrypted << cipher.final

      return encrypted
    end

    # Decrypt the given data with the AES-256-CBC algorithm using the
    # given passphrase. Returns 'nil' if there is any kind of error in
    # the decryption process. Distantly based upon:
    #
    #   http://www.bigbold.com/snippets/posts/show/576
    #
    def decrypt(data, passphrase)
      cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      cipher.decrypt

      cipher.key = Digest::SHA256.digest(passphrase)
      cipher.iv  = obtain_iv(passphrase)

      decrypted  = cipher.update(data)
      decrypted << cipher.final

      return decrypted
    rescue
      return nil
    end

    # Encrypt and base-64 encode the given data with the given passphrase.
    # Returns the encoded result.
    #
    def encode(data, passphrase)
      [encrypt(data, passphrase)].pack('m1000000') # Stupid long number to avoid "\n" in the output
    end

    # Decrypt and base-64 decode the given data with the given passphrase.
    # Returns the decoded result or 'nil' on error.
    #
    def decode(data, passphrase)
      decrypt(data.unpack('m').first, passphrase)
    rescue
      return nil
    end

    # "Scramble" a passphrase. Cookie data encryption is done purely so that
    # some hypothetical malicious user cannot easily examine or modify the
    # cookie contents for some nefarious purpose. Encryption is done at the
    # head end. We need to be able to decrypt in the absence of any other
    # information. A fixed passphrase thus needs to be used, but it cannot be
    # included in the source code or anyone can read the cookie contents! To
    # work around this, transform the passphrase into 32 bytes of data from
    # the random pool if asked. The random pool is not known to the outside
    # world so security is improved (albeit far from perfect, but this is all
    # part of little more than an anti-spam measure - not Fort Knox!).
    #
    def scramble_passphrase(passphrase)

      # Generate a 16-byte hash of the passphrase using the MD5 algorithm. Get
      # this as a string of hex digits and convert that into an integer. Strip
      # off the top bits (since we've no more reason to believe that the top
      # bits contain more randomly varying data than the bottom bits) so that
      # the number is bound to between zero and the random pool size, minus
      # 33, thus providing an offset into the file from which we can safely
      # read 32 bytes of data.

      offset = Digest::MD5.hexdigest(passphrase).hex % (@rnd_size - 32)

      # Return 32 bytes of data from the random pool at the calculated offset.

      return @rnd_data[offset..offset + 31]
    end

  private

    # Obtain an initialization vector (IV) of 32 bytes (256 bits) length based
    # on external data loaded when the object was created. Since the data
    # content is unknown, the IV is unknown. This is important; see:
    #
    #   http://www.ciphersbyritter.com/GLOSSARY.HTM#CipherBlockChaining
    #
    # Weakness: An offset into the supplied data is generated from the given
    # passphrase. Since the data is cached internally, the same IV will be
    # produced for any given passphrase (this is as much a feature as it is a
    # weakness, since the encryption and decryption routines rely on it).
    #
    # The passphrase scrambler is used to do the back-end work. Since the
    # caller may have already scrambled the passphrase once, scrambled data is
    # used as input; we end up scrambling it twice. This is a desired result -
    # we don't want the IV being the data that's actually also used for the
    # encryption passphrase.
    #
    def obtain_iv(passphrase)
      return scramble_passphrase(passphrase)
    end

  end # Crypto class

  #######################################################################
  # Class:   Roles                                                      #
  #          By Hipposoft, 2006                                         #
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
              :admin       => 'Administrator',
              :webmaster   => 'Webmaster',
              :privileged  => 'Privileged user',
              :normal      => 'Normal user'
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
    def initialize(first_ever_user = false)
      if (first_ever_user)
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

      return human_names.join(', ')
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
  #          By Hipposoft, 2006                                         #
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
    # to indicate permission for the general public - no login required.
    #
    # Example mapping for a generic controller used as a default parameter,
    # though you'd almost certainly always want to provide alternatives. It
    # requires a logged in user for new, create, edit and update; a logged
    # in user that's any privilege level above normal for delete; but will
    # let anyone at all list or show items.
    #
    def initialize(pmap = {
                            :new     => [ :admin, :webmaster, :privileged, :normal ],
                            :create  => [ :admin, :webmaster, :privileged, :normal ],
                            :edit    => [ :admin, :webmaster, :privileged, :normal ],
                            :update  => [ :admin, :webmaster, :privileged, :normal ],
                            :delete  => [ :admin, :webmaster, :privileged ],
                            :list    => nil,
                            :show    => nil
                          })
      @permissions = pmap
    end

    # Does the given Roles object grant permission for the given action,
    # expressed as a string or symbol? Returns 'true' if so, else 'false'.
    #
    # If a role is given as some other type, an attempt is made to convert
    # it to a Roles object internally (so you could pass a role symbol,
    # string, array of symbols or strings, or comma-separated string).
    #
    def permitted?(roles, action)
      action = action.to_s.intern
      roles  = roles.to_authenticated_roles

      return false unless @permissions.include?(action)
      return true if @permissions[action].nil?
      return roles.include?(@permissions[action])
    end

  end # Permissions class

  #######################################################################
  # Module:  Core                                                       #
  #          Various authors                                            #
  #                                                                     #
  # Purpose: The core of acts_as_authenticated's authorisation          #
  #          functions (its AuthenticatedSystem module), modified to    #
  #          work with the other parts of HubSsoLib. You should include #
  #          this module to use its facilities.                         #
  #                                                                     #
  # Author:  Various; adaptation by A.D.Hodgkinson                      #
  #                                                                     #
  # History: 20-Oct-2006 (ADH): Integrated into HubSsoLib.              #
  #######################################################################

  module Core

    # Returns true or false if the user is logged in.
    # Preloads @hubssolib_current_user with the user model if they're logged in.
    def hubssolib_logged_in?
      (@hubssolib_current_user ||= (hubssolib_get_user_data || false)).is_a?(User)
    end

    # Accesses the current user from the session.
    def hubssolib_current_user
      @hubssolib_current_user if hubssolib_logged_in?
    end

    # Store the given user in the session.
    def hubssolib_current_user=(new_user)
      hubssolib_set_user_data(new_user)
      @hubssolib_current_user = new_user
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
      return classname.permissions.permitted?(self.hubssolib_current_user.roles, action)
    end

    # Filter method to enforce a login requirement.
    #
    # To require logins for all actions, use this in your controllers:
    #
    #   before_filter :login_required
    #
    # To require logins for specific actions, use this in your controllers:
    #
    #   before_filter :login_required, :only => [ :edit, :update ]
    #
    # To skip this in a subclassed controller:
    #
    #   skip_before_filter :login_required
    #
    def hubssolib_login_required
      # Uncomment for HTTP basic authentication support:
      #
      # username, passwd = get_auth_data
      # self.current_user ||= User.authenticate(username, passwd) || :false if username && passwd
      result = hubssolib_logged_in? && hubssolib_authorized? ? true : hubssolib_access_denied

      if (result == true)
        hubssolib_ensure_https
        hubssolib_check_session_expiry
      end
    end

    # Filter method to call to update the idle timeout, even for
    # methods

    def hubssolib_update_session_expiry
      # See also private method hubssolib_check_session_expiry
      @session[:last_used] = Time.now.utc
    end

    # Redirect as appropriate when an access request fails.
    #
    # The default action is to redirect to the login screen.
    #
    # Override this method in your controllers if you want to have special
    # behavior in case the user is not authorized
    # to access the requested action.  For example, a popup window might
    # simply close itself.
    def hubssolib_access_denied
      # Uncomment commented out code for XML service support.
      #
      #respond_to do |accepts|
      #  accepts.html do
          flash[:alert] = 'You do not have permission to carry out that action on this site.'
          flash.discard
          # We mean this: redirect_to :controller => 'account', :action => 'login'
          # ...except for the Hub, rather than the current application (whatever
          # it may be).
          redirect_to '/rails/hub/account/login'
      #  end
      #  accepts.xml do
      #    headers["Status"]           = "Unauthorized"
      #    headers["WWW-Authenticate"] = %(Basic realm="Web Password")
      #    render :text => "Could't authenticate you", :status => '401 Unauthorized'
      #  end
      #end
      false
    end

    # Store the URI of the current request in the session.
    #
    # We can return to this location by calling #redirect_back_or_default.
    def hubssolib_store_location
      session[:return_to] = request.request_uri
    end

    # Redirect to the URI stored by the most recent store_location call or
    # to the passed default.
    def hubssolib_redirect_back_or_default(default)
      session[:return_to] ? redirect_to_url(session[:return_to]) : redirect_to(default)
      session[:return_to] = nil
    end

    # Ensure the current request is carried out over HTTPS by redirecting
    # back to the current URL with the HTTPS protocol if it isn't.
    #
    def hubssolib_ensure_https
      redirect_to({ :protocol => 'https://' }) unless request.ssl?
    end

    # Inclusion hook to make #hubssolib_current_user, #hubssolib_logged_in?
    # and #hubssolib_authorized? available as ActionView helper methods.
    def self.included(base)
      base.send :helper_method, :hubssolib_current_user, :hubssolib_logged_in?, :hubssolib_authorized?
    end

    # Uncomment the following as part of enabling "remember me" functions:
    #
    ## When called with before_filter :login_from_cookie will check for an :auth_token
    ## cookie and log the user back in if apropriate
    #def login_from_cookie
    #  return unless cookies[:auth_token] && !logged_in?
    #  user = User.find_by_remember_token(cookies[:auth_token])
    #  if user && user.remember_token?
    #    user.remember_me
    #    self.hubssolib_current_user = user
    #    cookies[:auth_token] = { :value => self.hubssolib_current_user.remember_token , :expires => self.hubssolib_current_user.remember_token_expires_at }
    #    flash[:notice] = "Logged in successfully"
    #  end
    #end

  private

    # Enforce a logged in idle timeout; only to be called when an
    # action that requires login is being run.
    #
    def hubssolib_check_session_expiry

      return unless hubssolib_logged_in?

      if (@session[:last_used].class == Time and Time.now.utc - @session[:last_used] > IDLE_TIME_LIMIT)
        hubssolib_store_location
        # We mean this: redirect_to :controller => 'account', :action => 'expire'
        # ...except for the Hub, rather than the current application (whatever
        # it may be).
        redirect_to '/rails/hub/account/expire'
      else
        @session[:last_used] = Time.now.utc
      end
    end

    # Uncomment for HTTP basic authentication support:
    #
    ## gets BASIC auth info
    #def get_auth_data
    #  user, pass = nil, nil
    #  # extract authorisation credentials
    #  if request.env.has_key? 'X-HTTP_AUTHORIZATION'
    #    # try to get it where mod_rewrite might have put it
    #    authdata = request.env['X-HTTP_AUTHORIZATION'].to_s.split
    #  elsif request.env.has_key? 'HTTP_AUTHORIZATION'
    #    # this is the regular location
    #    authdata = request.env['HTTP_AUTHORIZATION'].to_s.split
    #  end
    #
    #  # at the moment we only support basic authentication
    #  if authdata && authdata[0] == 'Basic'
    #    user, pass = Base64.decode64(authdata[1]).split(':')[0..1]
    #  end
    #  return [user, pass]
    #end

    # Retrieve user data from the session data cookie.
    #
    def hubssolib_get_user_data
      crypto     = HubSsoLib::Crypto.new(RND_FILE_PATH)
      passphrase = crypto.scramble_passphrase(request.remote_ip)
      data       = cookies[SESSION_DATA_KEY]
      user       = nil

      if (data && data != '')
        user = Marshal.load(crypto.decode(data, passphrase))
      end

      return user
    rescue
      return nil
    end

    # Store user data in the session data cookie. Pass the user to store,
    # or 'nil' to clear the cookie.
    #
    def hubssolib_set_user_data(user)
      if (user.nil?)
        # Using cookies.delete(SESSION_DATA_KEY) *should* work but doesn't.
        # Set the cookie with nil data instead.
        data = nil
      else
        crypto     = HubSsoLib::Crypto.new(RND_FILE_PATH)
        passphrase = crypto.scramble_passphrase(request.remote_ip)
        data       = crypto.encode(Marshal.dump(user), passphrase)
      end

      cookies[SESSION_DATA_KEY] = {
                                    :value   => data,
                                    :expires => Time.now.utc + SESSION_DATA_EXPIRY,
                                    :path    => '/rails',
                                    :secure  => true
                                  }
    end

  end # Core module
end # HubSsoLib module

#######################################################################
# Classes: Standard class extensions for HubSsoLib Roles operations.  #
#          By Hipposoft, 2006                                         #
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
