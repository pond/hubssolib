require 'spec_helper'

RSpec.describe HubSsoLib::Crypto do

  let( :passphrase ) { "0123456789abcdef" }

  let( :base64_decoded_data ) {
    %Q{
      This \xE9 is a long string of things that can get quite wide and easily exceed 80 characters in length altogether
      which is a general string of things
      that has some linebreaks
    }.force_encoding(Encoding::ASCII_8BIT).gsub(/^\s+/, '').strip()
  }

  let( :base64_encoded_data ) {
    "VGhpcyDpIGlzIGEgbG9uZyBzdHJpbmcgb2YgdGhpbmdzIHRoYXQgY2FuIGdl\n" +
    "dCBxdWl0ZSB3aWRlIGFuZCBlYXNpbHkgZXhjZWVkIDgwIGNoYXJhY3RlcnMg\n" +
    "aW4gbGVuZ3RoIGFsdG9nZXRoZXIKd2hpY2ggaXMgYSBnZW5lcmFsIHN0cmlu\n" +
    "ZyBvZiB0aGluZ3MKdGhhdCBoYXMgc29tZSBsaW5lYnJlYWtz\n"
  }

  # https://stackoverflow.com/a/8106054
  #
  VALID_BASE64 = /^[a-zA-Z0-9+\/]+={0,2}$/

  shared_examples 'a random generator' do | entity, message |
    it "and generates the right amount (#{ message })" do
      data1 = entity.random_data( 32 )
      data2 = entity.random_data( 32 )
      data3 = entity.random_data( 41 )
      data4 = entity.random_data( 41 )

      expect( data1.length ).to eql( 32 )
      expect( data2.length ).to eql( 32 )
      expect( data3.length ).to eql( 41 )
      expect( data4.length ).to eql( 41 )

      expect( data1 ).to_not eql(data2)
      expect( data3 ).to_not eql(data4)
    end
  end

  it_behaves_like 'a random generator', HubSsoLib::Crypto,     'class'
  it_behaves_like 'a random generator', HubSsoLib::Crypto.new, 'instance'

  shared_examples 'a Base64 encoder' do | entity, message |
    it "and encodes into a single terminated line (#{ message })" do
      packed = entity.pack64( base64_decoded_data() )
      expect( packed ).to eql( base64_encoded_data() )
      expect( packed ).to match( VALID_BASE64 )
    end
  end

  it_behaves_like 'a Base64 encoder', HubSsoLib::Crypto,     'class'
  it_behaves_like 'a Base64 encoder', HubSsoLib::Crypto.new, 'instance'

  shared_examples 'a Base64 decoder' do | entity, message |
    it "and decodes from a single terminated line (#{ message })" do
      expect( entity.unpack64( base64_encoded_data() ) ).to eql( base64_decoded_data() )
    end
  end

  it_behaves_like 'a Base64 decoder', HubSsoLib::Crypto,     'class'
  it_behaves_like 'a Base64 decoder', HubSsoLib::Crypto.new, 'instance'

  it 'scrambles passphrases' do
    passphrase = "this is a passphrase"
    scrambled  = HubSsoLib::Crypto.new.scramble_passphrase( passphrase )

    expect(passphrase).to_not eql(scrambled)
    expect(scrambled.length).to eql(16)

    passphrase2 = "this is a different passphrase"
    scrambled2  = HubSsoLib::Crypto.new.scramble_passphrase( passphrase2 )

    expect(scrambled2).to_not eql(scrambled)
    expect(passphrase2).to_not eql(scrambled2)
    expect(scrambled2.length).to eql(16)
  end

  it 'encrypts and decrypts' do
    data      = base64_decoded_data()
    encrypted = HubSsoLib::Crypto.new.encrypt( data,      passphrase() )
    decrypted = HubSsoLib::Crypto.new.decrypt( encrypted, passphrase() )
    expect(decrypted).to eql(data)
  end

  it "encodes and decodes" do
    data      = base64_decoded_data()
    encrypted = HubSsoLib::Crypto.new.encode( data,      passphrase() )
    decrypted = HubSsoLib::Crypto.new.decode( encrypted, passphrase() )
    expect(decrypted).to eql(data)
    expect(encrypted).to match( VALID_BASE64 )
  end

  shared_examples 'an object encoder/decoder' do | entity, message |
    let( :user_email     ) { "test@test.com" }
    let( :user_id        ) { 23 }
    let( :user_member_id ) { 42 }
    let( :user_object    ) {
      user                = HubSsoLib::User.new
      user.user_email     = user_email()
      user.user_id        = user_id()
      user.user_member_id = user_member_id()
      user
    }

    it 'encodes and decodes' do
      encoded = entity.encode_object( user_object(), passphrase() )
      decoded = entity.decode_object( encoded,       passphrase() )

      expect( decoded ).to be_a( HubSsoLib::User )
      expect( decoded.user_email     ).to eql( user_email()     )
      expect( decoded.user_id        ).to eql( user_id()        )
      expect( decoded.user_member_id ).to eql( user_member_id() )
    end
  end

  it_behaves_like 'an object encoder/decoder', HubSsoLib::Crypto,     'class'
  it_behaves_like 'an object encoder/decoder', HubSsoLib::Crypto.new, 'instance'
end
