require 'spec_helper'

RSpec.describe HubSsoLib::Roles do
  context 'class methods' do
    it 'enumerates symbols' do
      expect( HubSsoLib::Roles.get_role_symbols().size ).to be > 1
    end

    it 'enumerates names' do
      expect( HubSsoLib::Roles.get_display_names().size ).to be > 1
    end

    it 'converts symbols to names' do
      symbols = HubSsoLib::Roles.get_role_symbols()
      names   = HubSsoLib::Roles.get_display_names()

      symbols.each_with_index do | symbol, index |
        expect( HubSsoLib::Roles.get_display_name( symbol ) ).to eql( names[ index ] )
      end
    end

    it 'constructs a normal user' do
      roles = HubSsoLib::Roles.new
      expect( roles.include?( HubSsoLib::Roles::NORMAL ) ).to eql( true  )
      expect( roles.include?( HubSsoLib::Roles::ADMIN  ) ).to eql( false )
    end

    it 'constructs an admin user' do
      roles = HubSsoLib::Roles.new( true )
      expect( roles.include?( HubSsoLib::Roles::NORMAL ) ).to eql( false )
      expect( roles.include?( HubSsoLib::Roles::ADMIN  ) ).to eql( true  )
    end
  end

  context 'instance methods' do
    subject() { HubSsoLib::Roles.new }

    it 'adds roles' do
      subject().add( HubSsoLib::Roles::ADMIN )

      expect( subject().include?( HubSsoLib::Roles::NORMAL ) ).to eql( true )
      expect( subject().include?( HubSsoLib::Roles::ADMIN  ) ).to eql( true )
    end

    it 'deletes roles' do
      subject().add( HubSsoLib::Roles::ADMIN )

      expect( subject().include?( HubSsoLib::Roles::NORMAL ) ).to eql( true )
      expect( subject().include?( HubSsoLib::Roles::ADMIN  ) ).to eql( true )

      subject().delete( HubSsoLib::Roles::ADMIN )

      expect( subject().include?( HubSsoLib::Roles::NORMAL ) ).to eql( true  )
      expect( subject().include?( HubSsoLib::Roles::ADMIN  ) ).to eql( false )
    end

    it 'clears roles' do
      subject().add( HubSsoLib::Roles::ADMIN )

      expect( subject().include?( HubSsoLib::Roles::NORMAL ) ).to eql( true )
      expect( subject().include?( HubSsoLib::Roles::ADMIN  ) ).to eql( true )

      subject().clear()

      expect( subject().include?( HubSsoLib::Roles::NORMAL ) ).to eql( false )
      expect( subject().include?( HubSsoLib::Roles::ADMIN  ) ).to eql( false )
    end

    it 'converts to a string' do
      subject().add( HubSsoLib::Roles::ADMIN )

      expect( subject().to_s ).to eql( "#{ HubSsoLib::Roles::NORMAL },#{ HubSsoLib::Roles::ADMIN }" )
    end

    it 'converts to an array' do
      roles = HubSsoLib::Roles.new
      subject().add( HubSsoLib::Roles::ADMIN )

      expect( subject().to_a ).to eql( [ HubSsoLib::Roles::NORMAL, HubSsoLib::Roles::ADMIN ] )
    end

    it 'converts to a humanised string' do
      subject().add( HubSsoLib::Roles::ADMIN )

      normal_name = HubSsoLib::Roles.get_display_name( HubSsoLib::Roles::NORMAL )
      admin_name  = HubSsoLib::Roles.get_display_name( HubSsoLib::Roles::ADMIN  )

      expect( subject().to_human_s ).to eql( "#{ normal_name } and #{ admin_name }" )
    end

    it 'returns self' do
      expect( subject().to_authenticated_roles() ).to eql( subject() )
    end

    it 'validates' do
      subject().add( HubSsoLib::Roles::ADMIN )
      expect( subject().validate() ).to eql( true )

      subject().add( :random )
      expect( subject().validate() ).to eql( false )
    end

    it 'checks inclusion via Symbol' do
      subject().add( 'random' )
      expect( subject().include?( :random ) ).to eql( true )
    end

    it 'checks inclusion via String' do
      subject().add( :random )
      expect( subject().include?( 'random' ) ).to eql( true )
    end

    it 'aliases include? and includes?' do
      subject().add( :random )

      expect( subject().include?(  :random  ) ).to eql( true  )
      expect( subject().includes?( :random  ) ).to eql( true  )

      expect( subject().include?(  :missing ) ).to eql( false )
      expect( subject().includes?( :missing ) ).to eql( false )
    end
  end
end
