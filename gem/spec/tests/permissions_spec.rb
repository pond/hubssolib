require 'spec_helper'

RSpec.describe HubSsoLib::Permissions do
  let( :map ) {
    {
      :new     => [ :admin, :webmaster, :privileged, :normal ],
      :create  => [ :admin, :webmaster, :privileged ],
      :edit    => [ :admin, :webmaster ],
      :update  => [ :admin ],
      :delete  => [],
      :list    => nil,
      :show    => nil
    }
  }

  it 'checks Role objects with one role' do
    p = HubSsoLib::Permissions.new( map() )

    map().keys.each do | action |
      all_permitted_roles = map()[ action ]
      admin               = HubSsoLib::Roles.new( true )
      random              = HubSsoLib::Roles.new

      random.clear()
      random.add( :random )

      if ( all_permitted_roles.nil? )
        expect( p.permitted?( admin, action ) ).to eql( true )
      elsif ( all_permitted_roles.empty? )
        expect( p.permitted?( admin, action ) ).to eql( false )
      else
        all_permitted_roles.each do | permitted_role |
          roles = HubSsoLib::Roles.new
          roles.clear()
          roles.add( permitted_role )

          expect( p.permitted?( roles, action ) ).to eql( true )
          expect( p.permitted?( random, action ) ).to eql( false )
        end
      end
    end
  end

  it 'checks Role objects with many roles' do
    p = HubSsoLib::Permissions.new( map() )

    map().keys.each do | action |
      all_permitted_roles = map()[ action ]
      admin               = HubSsoLib::Roles.new( true )

      if ( ! all_permitted_roles.nil? && ! all_permitted_roles.empty? )
        roles = HubSsoLib::Roles.new
        roles.clear()

        all_permitted_roles.each do | permitted_role |
          roles.add( permitted_role )
        end

        roles.add( :random ) # Should be ignored - other required roles are present

        expect( p.permitted?( roles, action ) ).to eql( true )
      end
    end
  end

  it 'prmotes Arrays to roles' do
    p = HubSsoLib::Permissions.new( map() )

    map().keys.each do | action |
      all_permitted_roles = map()[ action ]
      admin               = [ HubSsoLib::Roles::ADMIN ]
      random              = [ :random ]

      if ( all_permitted_roles.nil? )
        expect( p.permitted?( admin, action ) ).to eql( true )
      elsif ( all_permitted_roles.empty? )
        expect( p.permitted?( admin, action ) ).to eql( false )
      else
        all_permitted_roles.each do | permitted_role |
          roles = [ permitted_role ]

          expect( p.permitted?( roles, action ) ).to eql( true )
          expect( p.permitted?( random, action ) ).to eql( false )
        end
      end
    end
  end

  it 'promotes Strings to roles' do
    p = HubSsoLib::Permissions.new( map() )

    map().keys.each do | action |
      all_permitted_roles = map()[ action ]

      if ( all_permitted_roles.nil? )
        expect( p.permitted?( HubSsoLib::Roles::ADMIN.to_s, action ) ).to eql( true )
      elsif ( all_permitted_roles.empty? )
        expect( p.permitted?( HubSsoLib::Roles::ADMIN.to_s, action ) ).to eql( false )
      else
        all_permitted_roles.each do | permitted_role |
          expect( p.permitted?( permitted_role.to_s, action ) ).to eql( true )
          expect( p.permitted?( 'random', action ) ).to eql( false )
        end
      end
    end
  end

  it 'promotes Symbols to roles' do
    p = HubSsoLib::Permissions.new( map() )

    map().keys.each do | action |
      all_permitted_roles = map()[ action ]

      if ( all_permitted_roles.nil? )
        expect( p.permitted?( HubSsoLib::Roles::ADMIN.to_s.to_sym, action ) ).to eql( true )
      elsif ( all_permitted_roles.empty? )
        expect( p.permitted?( HubSsoLib::Roles::ADMIN.to_s.to_sym, action ) ).to eql( false )
      else
        all_permitted_roles.each do | permitted_role |
          expect( p.permitted?( permitted_role.to_s.to_sym, action ) ).to eql( true )
          expect( p.permitted?( :random, action ) ).to eql( false )
        end
      end
    end
  end
end
