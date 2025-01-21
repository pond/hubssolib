class RemoveLengthLimits < ActiveRecord::Migration[7.2]
  def up
    change_table :users do |t|
      t.change :crypted_password,    :text
      t.change :salt,                :text
      t.change :password_reset_code, :text
      t.change :activation_code,     :text
      t.change :remember_token,      :text

      t.change :email,               :text
      t.change :real_name,           :text
      t.change :roles,               :text
    end
  end

  def down
    change_table :users do |t|
      t.change :crypted_password,    :string, limit: 40
      t.change :salt,                :string, limit: 40
      t.change :password_reset_code, :string, limit: 40
      t.change :activation_code,     :string, limit: 40
      t.change :remember_token,      :string, limit: 255

      t.change :email,               :string
      t.change :real_name,           :string, limit: 128
      t.change :roles,               :string
    end
  end
end
