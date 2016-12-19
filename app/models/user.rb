class User < ApplicationRecord

  # Allows to create attributes for the user model - see remember
  attr_accessor :remember_token

  has_secure_password # checks for presence of password (can be whitespace though)

  before_save { self.email = email.downcase }
  # Alternates
  # before_save {self.email = self.email.downcase }
  # before_save { email.downcase! }

  validates(:name, presence: true, length: { maximum: 50 })

  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i

  validates(:email,
    presence: true,
    length: { maximum: 255 },
    format: { with: VALID_EMAIL_REGEX },
    uniqueness: { case_sensitive: false })

  validates(:password, presence: true, length: { minimum: 5 }, allow_nil: true ) # allow_nil: true - lets a user update their account information without having to recreate a password everytime

  # presence: true checks for .blank? NOT --> .empty?

  # ~~~~~ METHODS ~~~~~

  # NOTE: the below 2 methods could be defined in the following formats.
  # def User.digest end; def self.digest end; or class << self, def digest(string) end

  # Returns the hash digest of the given string.
  def User.digest(string)
    cost = ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST :
        BCrypt::Engine.cost
    BCrypt::Password.create(string, cost: cost)
  end

  # Returns a random token
  def User.new_token
    SecureRandom.urlsafe_base64
  end

  # Remembers a user in the database for use in persistent sessions - allows to override the login method
  # test in console => x=User.first; x.remember; x.remember_token; x.remember_digest
  def remember
    # NOTE: without using self, remember would be created as a local variable.
    # including self, sets remember_token to the user model
    self.remember_token = User.new_token
    update_attribute(:remember_digest, User.digest(remember_token))
  end

  # Returns true if the given token matches the digest.
  # Note: the remember_token listed below is NOT the same as the remember_token called in attr_accessor. This is a variable local to the method.
  # remember_digest is the equivalent of self.remember_digest
  def authenticated?(remember_token)
    return false if remember_digest.nil? # if => false, remainder of block isn't executed
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end

  # forgets a user
  def forget
    update_attribute(:remember_digest, nil)
  end



end
