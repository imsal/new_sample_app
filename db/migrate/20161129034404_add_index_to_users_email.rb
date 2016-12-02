class AddIndexToUsersEmail < ActiveRecord::Migration[5.0]
  def change
    add_index :users, :email, unique: true # Rejects duplicate email addresses in the database
  end
end
