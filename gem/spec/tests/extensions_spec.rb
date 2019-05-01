require 'spec_helper'

RSpec.describe 'Extensions' do
  it 'converts Strings to Roles' do
    roles = "admin".to_authenticated_roles

    expect( roles ).to be_a( HubSsoLib::Roles )
    expect( roles.include?( "admin" ) ).to eql( true )
  end

  it 'converts Symbols to Roles' do
    roles = :admin.to_authenticated_roles

    expect( roles ).to be_a( HubSsoLib::Roles )
    expect( roles.include?( "admin" ) ).to eql( true )
  end

  it 'converts Arrays of Strings to Roles' do
    roles = [ 'admin' ].to_authenticated_roles

    expect( roles ).to be_a( HubSsoLib::Roles )
    expect( roles.include?( "admin" ) ).to eql( true )
  end

  it 'converts Arrays of Symbols to Roles' do
    roles = [ :admin ].to_authenticated_roles

    expect( roles ).to be_a( HubSsoLib::Roles )
    expect( roles.include?( "admin" ) ).to eql( true )
  end

end
