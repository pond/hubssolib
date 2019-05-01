require 'spec_helper'

RSpec.describe HubSsoLib::Session do
  let( :accessors ) {
    [
      :session_last_used,
      :session_return_to,
      :session_flash,
      :session_user
    ]
  }

  it 'initialises' do
    HubSsoLib::Session.new()
  end

  it 'has appropriate accessors' do
    u = HubSsoLib::Session.new()

    accessors().each do | accessor |
      u.send( "#{ accessor }=", "Testing #{ accessor }" )
    end

    accessors().each do | accessor |
      expect( u.send( accessor ) ).to eql( "Testing #{ accessor }" )
    end
  end
end
