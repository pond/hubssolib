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
#          08-Dec-2006 (ADH): DRB URI, path prefix and random file    #
#                             path come from environment variables.   #
#######################################################################

module HubSsoLib

  require 'drb'

  # DRb connection
  HUBSSOLIB_DRB_URI = ENV['HUB_CONNECTION_URI']

  # Location of Hub application root.
  HUB_PATH_PREFIX = ENV['HUB_PATH_PREFIX']

  # Time limit, *in seconds*, for the account inactivity timeout.
  # If a user performs no Hub actions during this time they will
  # be automatically logged out upon their next action.
  HUBSSOLIB_IDLE_TIME_LIMIT = 60 * 60

  # Random file location.
  HUBSSOLIB_RND_FILE_PATH = ENV['HUB_RANDOM_FILE']

  # Shared cookie name.
  HUBSSOLIB_COOKIE_NAME = 'hubapp_shared_id'

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

    # Generate a series of pseudo-random bytes of the given length.
    #
    def self.random_data(size)
      data = ''
      size.times { data << rand(256) }
      data
    end

    def random_data(size)
      HubSsoLib::Crypto.random_data(size)
    end

    # Encode some given data in base-64 format with no line breaks.
    #
    def self.pack64(data)
      [data].pack('m1000000') # Stupid long number to avoid "\n" in the output
    end

    def pack64(data)
      HubSsoLib::Crypto.pack64(data)
    end

    # Decode some given data from base-64 format with no line breaks.
    #
    def self.unpack64(data)
      data.unpack('m').first
    end

    def unpack64(data)
      HubSsoLib::Crypto.unpack64(data)
    end

    # Encrypt the given data with the AES-256-CBC algorithm using the
    # given passphrase. Returns the encrypted result in a string.
    # Distantly based upon:
    #
    #   http://www.bigbold.com/snippets/posts/show/576
    #
    # In the context of Hub, the passphrase tends to be fixed per IP
    # address (albeit unknown to the public) and the IV is derived from
    # it. This means the same data will encode to the same result. With
    # the source data having some parts which are invariant, security
    # is compromised. To avoid this, data is prefixed by a quantity of
    # random bytes, effectively supplementing the IV and ensuring that
    # different size and content data is generated each time.
    #
    def encrypt(data, passphrase)
      cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
      cipher.encrypt

      cipher.key = Digest::SHA256.digest(passphrase)
      cipher.iv  = obtain_iv(passphrase)

      rsize = rand(32)
      data  = '' << rsize << random_data(rsize) << data

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

      rsize = decrypted[0]
      return decrypted[rsize + 1..-1]
    rescue
      return nil
    end

    # Encrypt and base-64 encode the given data with the given passphrase.
    # Returns the encoded result.
    #
    def encode(data, passphrase)
      pack64(encrypt(data, passphrase))
    end

    # Decrypt and base-64 decode the given data with the given passphrase.
    # Returns the decoded result or 'nil' on error.
    #
    def decode(data, passphrase)
      decrypt(unpack64(data), passphrase)
    rescue
      return nil
    end

    # Class method that takes an object and passphrase and encrypts
    # the result. The passphrase is scrambled internally using data
    # not available to the public, the object serialised (so it must
    # support serialisation), encrypted and base-64 encoded, and the
    # 7-bit safe string result returned. On failure, exceptions will
    # be raised (failure is not expected).
    #
    def self.encode_object(object, passphrase)
      crypto     = HubSsoLib::Crypto.new(HUBSSOLIB_RND_FILE_PATH)
      passphrase = crypto.scramble_passphrase(passphrase)

      return crypto.encode(Marshal.dump(object), passphrase)
    end

    def encode_object(object, passphrase)
      HubSsoLib::Crypto.encode_object(object, passphrase)
    end

    # Class method that takes output from Crypto.encode_object and
    # decodes it, returning an object reference. Since failure may
    # result from invalid data input and this can be a common case,
    # rather than raise an exception as with Crypto.encode_object,
    # this method returns 'nil' should there be any decode problems.
    #
    def self.decode_object(data, passphrase)
      crypto     = HubSsoLib::Crypto.new(HUBSSOLIB_RND_FILE_PATH)
      passphrase = crypto.scramble_passphrase(passphrase)
      object     = nil

      if (data && !data.empty?)
        object = Marshal.load(crypto.decode(data, passphrase))
      end

      return object
    rescue
      return nil
    end

    def decode_object(data, passphrase)
      HubSsoLib::Crypto.decode_object(data, passphrase)
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
  #          By Hipposoft, 2006                                         #
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
    include DRb::DRbUndumped

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
  #          By Hipposoft, 2006                                         #
  #                                                                     #
  # Purpose: Session support object, used to store session metadata in  #
  #          an insecure cross-application cookie.                      #
  #                                                                     #
  # Author:  A.D.Hodgkinson                                             #
  #                                                                     #
  # History: 22-Oct-2006 (ADH): Created.                                #
  #######################################################################

  class Session
    include DRb::DRbUndumped

    attr_accessor :session_last_used
    attr_accessor :session_return_to
    attr_accessor :session_flash
    attr_accessor :session_user

    def initialize
      @session_last_used = Time.now.utc
      @session_return_to = nil
      @session_flash     = {}
      @session_user      = HubSsoLib::User.new
    end
  end # Session class

  #######################################################################
  # Class:   SessionFactory                                             #
  #          By Hipposoft, 2006                                         #
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
      @sessions = {}
    end

    def get_session(key)
      unless (@sessions.has_key? key)
        @sessions[key] = HubSsoLib::Session.new
      end

      return @sessions[key]
    end
  end

  #######################################################################
  # Module:  Server                                                     #
  #          By Hipposoft, 2006                                         #
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
      DRb.start_service(HUBSSOLIB_DRB_URI, HubSsoLib::SessionFactory.new)
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
      puser   = hubssolib_get_user_roles.to_s

      return (puser && !puser.empty? && puser != pnormal)
    end

    # Log out the user. Very few applications should ever need to call this,
    # though Hub certainly does and it gets used internally too.
    #
    def hubssolib_log_out
      # Causes the "hubssolib_current_[foo]=" methods to run, which
      # deal with everything else.
      self.hubssolib_current_user    = nil
      self.hubssolib_current_session = nil
    end

    # Accesses the current user, via the DRb server if necessary
    #
    def hubssolib_current_user
      hubssolib_get_user_data
    end

    # Store the given user data in the cookie
    #
    def hubssolib_current_user=(new_user)
      hubssolib_set_user_data(new_user)
    end

    # Accesses the current session from the cookie. Creates a new
    # session object if need be.
    #
    def hubssolib_current_session
      @hubssolib_current_session ||= hubssolib_get_session_data
    end

    # Store the given session data.
    #
    def hubssolib_current_session=(new_session)
      @hubssolib_current_session = new_session
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

      if (self.class.respond_to? :hubssolib_permissions)
        login_is_required = !self.class.hubssolib_permissions.permitted?('', action_name)
      else
        login_is_required = false
      end

      # If we require login but we're logged out, redirect to Hub login.

      logged_in = hubssolib_logged_in?

      if (login_is_required and logged_in == false)
        hubssolib_store_location
        return hubssolib_must_login
      end

      # If we reach here the user is either logged, or the method does
      # not require them to be. In the latter case, if we're not logged
      # in there is no more work to do - exit early.

      return true unless logged_in # true -> let action processing continue

      # So we reach here knowing we're logged in, but the action may or
      # may not require authorisation.

      unless (login_is_required)

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

      else

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

      end
    end

    # Main after_filter method to tidy up after running state changes.
    #
    def hubssolib_afterwards
      # Nothing to do right now; maybe in future...
    end

    # Store the URI of the current request in the session, or store the
    # optional supplied specific URI.
    #
    # We can return to this location by calling #redirect_back_or_default.
    #
    def hubssolib_store_location(uri_str = request.request_uri)

      if (uri_str && !uri_str.empty?)
        uri_str = hubssolib_promote_uri_to_ssl(uri_str, request.host)
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

      url ? redirect_to_url(url) : redirect_to(default)
    end

    # Take a URI and pass an optional host parameter. Decomposes the URI,
    # sets the host you provide (or leaves it alone if you omit the
    # parameter), then forces the scheme to 'https'. Returns the result
    # as a flat string.

    def hubssolib_promote_uri_to_ssl(uri_str, host = nil)
      uri = URI.parse(uri_str)
      uri.host = host if host
      uri.scheme = 'https'
      return uri.to_s
    end

    # Ensure the current request is carried out over HTTPS by redirecting
    # back to the current URL with the HTTPS protocol if it isn't. Returns
    # 'true' if not redirected (already HTTPS), else 'false'.
    #
    def hubssolib_ensure_https
      unless request.ssl?
        # This isn't reliable: redirect_to({ :protocol => 'https://' })
        redirect_to (hubssolib_promote_uri_to_ssl(request.request_uri, request.host))
        return false
      else
        return true
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
      f[symbol] = message
      self.hubssolib_current_session.session_flash = f
    end

    def hubssolib_clear_flash
      return unless self.hubssolib_current_session
      self.hubssolib_current_session.session_flash = {}
    end

    # Helper methods to output flash data. It isn't merged into the standard
    # application flash with a filter because the rather daft and difficult
    # to manage lifecycle model of the standard flash gets in the way.
    #
    # First, return tags for a flash using the given key, clearing the
    # result in the flash hash now it has been used.
    #
    def hubssolib_flash_tag(key)
      value = hubssolib_get_flash[key]

      if (value)
        hubssolib_set_flash(key, nil)
        return "<h2 align=\"left\" class=\"#{key}\">#{value}</h2><p />"
      else
        return ''
      end
    end

    # Next, return tags for a standard application flash using the given key.
    #
    def hubssolib_standard_flash_tag(key)
      value = flash[key] if defined?(flash)

      if (value)
        flash.delete(key)
        return "<h2 align=\"left\" class=\"#{key}\">#{value}</h2><p />"
      else
        return ''
      end
    end

    # Return flash tags for known keys, then all remaining keys, from both
    # the cross-application and standard standard flash hashes.
    #
    def hubssolib_flash_tags
      # These known key values are used to guarantee an order in the output
      # for cases where multiple messages are defined.

      tags  = hubssolib_flash_tag(:notice)    <<
              hubssolib_flash_tag(:attention) <<
              hubssolib_flash_tag(:alert)

      tags << hubssolib_standard_flash_tag(:notice)    <<
              hubssolib_standard_flash_tag(:attention) <<
              hubssolib_standard_flash_tag(:alert)

      # Now pick up anything else.

      hubssolib_get_flash.each do |key, value|
        tags << hubssolib_flash_tag(key) if (value and !value.empty?)
      end

      flash.each do |key, value|
        tags << hubssolib_standard_flash_tag(key) if (value and !value.empty?)
      end if defined?(flash)

      return tags
    end

    # Retrieve the message of an exception stored as an object in the given
    # string.
    #
    def hubssolib_get_exception_message(id_data)
      hubssolib_get_exception_data(id_data)
    end

    # Inclusion hook to make various methods available as ActionView
    # helper methods.
    #
    def self.included(base)
      base.send :helper_method,
                :hubssolib_current_user,
                :hubssolib_unique_name,
                :hubssolib_logged_in?,
                :hubssolib_authorized?,
                :hubssolib_privileged?,
                :hubssolib_flash_tags
    rescue
      # We're not always included in controllers...
      nil
    end

  private

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
      (request.method != :post && last_used && Time.now.utc - last_used > HUBSSOLIB_IDLE_TIME_LIMIT)
    end

    # Retrieve data from a given cookie with encrypted contents.
    #
    def hubssolib_get_secure_cookie_data(name)
      return HubSsoLib::Crypto.decode_object(cookies[name], request.remote_ip)
    end

    # Set the given cookie to a value of the given data, which
    # will be encrypted.
    #
    def hubssolib_set_secure_cookie_data(name, value)
      if (@hubssolib_have_written_cookie)
        raise "HubSsoLib: Attmept to set cookie '#{name}' more than once"
      end

      @hubssolib_have_written_cookie = true

      # Using cookies.delete *should* work but doesn't. Set the
      # cookie with nil data instead.

      data = value.nil? ? nil : HubSsoLib::Crypto.encode_object(value, request.remote_ip)

      # No expiry time; to aid security, use session cookies only.

      cookies[name] = {
                        :value   => data,
                        :path    => '/rails',
                        :secure  => true
                      }
    end

    # Retrieve user data from the DRb server.
    #
    def hubssolib_get_user_data
      user = self.hubssolib_current_session ? self.hubssolib_current_session.session_user : nil

      if (user && user.user_id)
        return user
      else
        return nil
      end
    end

    def hubssolib_set_user_data(user)
      self.hubssolib_current_session.session_user = user
    end

    def hubssolib_get_session_data

      # If we're not using SSL, forget it
      return nil unless request.ssl?

      # If we've no cookie, we need a new session ID
      key = hubssolib_get_secure_cookie_data(HUBSSOLIB_COOKIE_NAME)

      unless (key)
        key = HubSsoLib::Crypto.pack64(HubSsoLib::Crypto.random_data(48))
        hubssolib_set_secure_cookie_data(HUBSSOLIB_COOKIE_NAME, key)
      end

      DRb.start_service()

      factory = DRbObject.new_with_uri(HUBSSOLIB_DRB_URI)
      return factory.get_session(key)

    rescue Exception => e

      # At this point there tends to be no Session data, so we're
      # going to have to encode the exception data into the URI...

      suffix   = '/' + CGI::escape(hubssolib_set_exception_data(e))
      new_path = HUB_PATH_PREFIX + '/tasks/service'
      redirect_to new_path + suffix unless request.path.include?(new_path)
      return nil
    end

    def hubssolib_set_session_data(session)
      # Nothing to do presently - DRb handles everything
    end

    # Encode exception data into a string suitable for using in a URL
    # if CGI escaped first. Pass the exception object; stores only the
    # message.
    #
    def hubssolib_set_exception_data(e)
      HubSsoLib::Crypto.encode_object(e.message, request.remote_ip)
    end

    # Decode exception data encoded with hubssolib_set_exception_data.
    # Returns the originally stored message string or 'nil' if there
    # are any decoding problems. Pass the encoded data.
    #
    def hubssolib_get_exception_data(data)
      HubSsoLib::Crypto.decode_object(data, request.remote_ip)
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
