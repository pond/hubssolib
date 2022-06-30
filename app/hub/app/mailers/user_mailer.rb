class UserMailer < ApplicationMailer
  def signup_notification
    @user = params[ :user ]
    @url  = url_for(:controller => :account,
                    :action     => :activate,
                    :id         => @user.activation_code,
                    :protocol   => 'https')

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Please activate your new web site account"
    )
  end

  def activation
    @user = params[ :user ]
    @url  = root_url()

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account has been activated"
    )
  end

  def forgot_password
    @user = params[ :user ]
    @url  = url_for(:controller => :account,
                    :action     => :reset_password,
                    :id         => @user.password_reset_code,
                    :protocol   => 'https')

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Request to change a web site account password"
    )
  end

  def reset_password
    @user = params[ :user ]
    @url  = EMAIL_ADMIN

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account password has been reset"
    )
  end

  def destruction
    @user = params[ :user ]
    @url  = EMAIL_ADMIN

    mail(
      to:      @user.email,
      subject: "[#{INSTITUTION_NAME_SHORT}] Your web site account has been deleted"
    )
  end
end
