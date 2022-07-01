require 'spec_helper'

RSpec.describe HubSsoLib::SessionFactory do
  subject() { HubSsoLib::SessionFactory.new() }

  it 'returns new sessions' do
    expect( subject().get_hub_session_proxy( :foo , '127.0.0.1') ).to be_a( HubSsoLib::Session )
  end

  it 'returns existing sessions' do
    foo_user = double('user', user_id: :foo)
    bar_user = double('user', user_id: :bar)

    foo   = subject().get_hub_session_proxy( :foo, '127.0.0.1' ); foo.session_user = foo_user
    bar   = subject().get_hub_session_proxy( :bar, '127.0.0.1' ); bar.session_user = bar_user
    refoo = subject().get_hub_session_proxy( foo.session_key_rotation, '127.0.0.1' )

    expect(foo.session_user.user_id).to eql(:foo)
    expect(bar.session_user.user_id).to eql(:bar)

    expect(  bar.session_user.user_id).to_not eql(foo.session_user.user_id)
    expect(refoo.session_user.user_id).to     eql(foo.session_user.user_id)
  end

  it 'rotates session keys' do
    foo_user = double('user', user_id: :foo)
    bar_user = double('user', user_id: :bar)

    # First the 'right way' - second call uses key rotation from first call.
    #
    foo       = subject().get_hub_session_proxy( :foo, '127.0.0.1' ); foo.session_user = foo_user
    new_key   = foo.session_key_rotation
    refoo     = subject().get_hub_session_proxy( new_key, '127.0.0.1' )
    newer_key = foo.session_key_rotation

    expect(foo.object_id           ).to eql(refoo.object_id           )
    expect(foo.session_user.user_id).to eql(refoo.session_user.user_id)

    expect(new_key).to_not eql(newer_key)

    # Now the 'wrong way' - second call identical to first; yields new session,
    # without the previously stored user.
    #
    bar   = subject().get_hub_session_proxy( :bar, '127.0.0.1' ); bar.session_user = bar_user
    rebar = subject().get_hub_session_proxy( :bar, '127.0.0.1' )

    expect(  bar.session_user.user_id).to eql(:bar)
    expect(rebar.session_user.user_id).to be_nil
  end

  it 'enumerates sessions' do
    foo  = subject().get_hub_session_proxy( :foo, '127.0.0.1' )
    bar  = subject().get_hub_session_proxy( :bar, '127.0.0.1' )
    list = subject().enumerate_hub_sessions()

    expect( list.values ).to match_array([ foo, bar ])
  end
end
