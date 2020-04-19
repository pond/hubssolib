require 'spec_helper'

RSpec.describe HubSsoLib::SessionFactory do
  subject() { HubSsoLib::SessionFactory.new() }

  it 'returns new sessions' do
    expect( subject().get_session( :foo ) ).to be_a( HubSsoLib::Session )
  end

  it 'returns existing sessions' do
    foo   = subject().get_session( :foo )
    bar   = subject().get_session( :bar )
    refoo = subject().get_session( :foo )

    expect( bar ).to_not eql( foo )
    expect( refoo ).to eql( foo )
  end

  it 'enumerates sessions' do
    foo  = subject().get_session( :foo )
    bar  = subject().get_session( :bar )
    list = subject().enumerate_hub_sessions()

    expect( list ).to eql( { :foo => foo, :bar => bar } )
  end
end
