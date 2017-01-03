class User < ApplicationRecord
  # Allows to create attributes for the user model - see remember
  attr_accessor :remember_token, :activation_token, :reset_token

  has_secure_password # checks for presence of password (can be whitespace though)

  before_save { self.email = email.downcase }
  # Alternates
  # before_save {self.email = self.email.downcase }
  # before_save { email.downcase! }
  before_save :downcase_email
  before_create :create_activation_digest

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
  # Checks to see whether remember_token or activation_token are true
  # attribute = :remember OR :activation
  # token = remember_token or activation_token via User Model
  def authenticated?(attribute, token)
    digest = send("#{attribute}_digest") # Could use self.send here but because we are in the user model, it is implied
    return false if digest.nil? # if => false, remainder of block isn't executed
    BCrypt::Password.new(digest).is_password?(token)
  end

  # forgets a user
  def forget
    update_attribute(:remember_digest, nil)
  end

  # Activates an account
  def activate
    update_columns(activated: true, activated_at: Time.now)
    # update_attribute(:activated, true)
    # update_attribute(:activated_at, Time.now)
  end

  # Sends the activation email
  def send_activation_email
    UserMailer.account_activation(self).deliver_now
  end

  # Sets the password reset attributes
  def create_reset_digest
    self.reset_token = User.new_token
    update_columns(reset_digest:  User.digest(reset_token), reset_sent_at: Time.zone.now)
    # The above block ensures that the database is only hit once during the method call
    # update_attribute(:reset_digest, User.digest(reset_token))
    # update_attribute(:reset_sent_at, Time.zone.now)
  end

  # Sends the password reset email
  def send_password_reset_email
    UserMailer.password_reset(self).deliver_now # via user_mailer.rb method
  end

  # Returns true if a password reset has expired
  def password_reset_expired?
    reset_sent_at < 2.hours.ago # The password reset was sent earlier than two hours ago.
  end

  private

  # Converts email to all lower case
  def downcase_email
    self.email.downcase!
  end

  # Creates and assigns the activation token and digest
  def create_activation_digest
    self.activation_token = User.new_token
    self.activation_digest = User.digest(activation_token)
  end



end
