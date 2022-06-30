class AddRealName < ActiveRecord::Migration[5.2]
  def self.up
    add_column "users", "real_name", :string, :limit => 128
  end

  def self.down
    remove_column "users", "real_name"
  end
end
