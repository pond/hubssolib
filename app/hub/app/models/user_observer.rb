class UserObserver < ActiveRecord::Observer
  def after_create(user)
    UserMailer.with(user: user).signup_notification().deliver_later()
  end

  def after_save(user)
    UserMailer.with(user: user).activation().deliver_later()      if user.recently_activated?
    UserMailer.with(user: user).forgot_password().deliver_later() if user.recently_forgot_password?
    UserMailer.with(user: user).reset_password().deliver_later()  if user.recently_reset_password?
  end
end
