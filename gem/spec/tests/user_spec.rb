require 'spec_helper'

RSpec.describe HubSsoLib::User do
  let( :accessors ) {
    [
      :user_salt,
      :user_roles,
      :user_updated_at,
      :user_activated_at,
      :user_real_name,
      :user_crypted_password,
      :user_remember_token_expires_at,
      :user_activation_code,
      :user_member_id,
      :user_id,
      :user_password_reset_code,
      :user_remember_token,
      :user_email,
      :user_created_at,
      :user_password_reset_code_expires_at
    ]
  }

  it 'initialises' do
    HubSsoLib::User.new()
  end

  it 'has appropriate accessors' do
    u = HubSsoLib::User.new()

    accessors().each do | accessor |
      u.send( "#{ accessor }=", "Testing #{ accessor }" )
    end

    accessors().each do | accessor |
      expect( u.send( accessor ) ).to eql( "Testing #{ accessor }" )
    end
  end
end
