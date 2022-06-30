require 'digest/sha1'

class User < ActiveRecord::Base
  before_create :make_activation_code

  # Virtual attribute for the unencrypted password
  attr_accessor :password

  validates_length_of       :password, :within => 4..40, :if => :password_required?
  validates_confirmation_of :password,                   :if => :password_required?

  validates_length_of       :email,     :within => 3..200
  validates_length_of       :real_name, :within => 3..200

  validates_uniqueness_of   :email, :case_sensitive => false

  before_save :encrypt_password

  def roles_array
    self.roles.to_authenticated_roles.to_a
  end

  def roles_array=(array)
    self.roles = roles.join(',')
  end

  # Authenticates a user by e-mail address and unencrypted password.  Returns the user or nil.
  def self.authenticate(email, password)
    # hide records with a nil activated_at
    u = self.where(['LOWER(email) = ? and activated_at IS NOT NULL', email.downcase]).first
    u && u.authenticated?(password) ? u : nil
  end

  # Encrypts some data with the salt.
  def self.encrypt(password, salt)
    Digest::SHA1.hexdigest("--#{salt}--#{password}--")
  end

  # Encrypts the password with the user salt
  def encrypt(password)
    self.class.encrypt(password, salt)
  end

  def authenticated?(password)
    crypted_password == encrypt(password)
  end

  # Activates the user in the database.
  def activate
    @activated = true
    self.activated_at = Time.now.utc
    self.activation_code = nil
    save(validate: false)
  end

  # Returns true if the user has just been activated.
  def recently_activated?
    activated = @activated
    @activated = false
    return activated
  end

  # Deal with forgotten passwords
  def forgot_password
    self.password_reset_code_expires_at = (Time.now.utc) + RESET_TIME_LIMIT
    self.make_password_reset_code
    save(validate: false)
    @forgotten_password = true
  end

  def reset_password
    # First update the password_reset_code before setting the
    # reset_password flag to avoid duplicate email notifications.
    self.password_reset_code_expires_at = nil
    self.password_reset_code            = nil
    save(validate: false)
    @reset_password = true
  end

  def recently_reset_password?
    reset_password = @reset_password
    @reset_password = false
    return reset_password
  end

  def recently_forgot_password?
    forgotten_password = @forgotten_password
    @forgotten_password = false
    return forgotten_password
  end

  def destroy
    UserMailer.with(user: self).destruction().deliver_later()
    super
  end

  protected
    # before filter
    def encrypt_password
      return if password.blank?
      self.salt = Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{email}--") if new_record?
      self.crypted_password = encrypt(password)
    end

    def password_required?
      crypted_password.blank? || !password.blank?
    end

    # Create a user activation code for activation e-mail messages
    def make_activation_code
      self.activation_code = Digest::SHA1.hexdigest(Time.now.to_s.split(//).sort_by {rand}.join)
    end

    # Make a password reset code for users who've forgotten their password
    def make_password_reset_code
      self.password_reset_code = Digest::SHA1.hexdigest(Time.now.to_s.split(//).sort_by {rand}.join)
    end
end
