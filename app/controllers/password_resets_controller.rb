class PasswordResetsController < ApplicationController
  def new
  end

  def edit
  end

  def create
    @user = User.find_by(email: params[:password_reset][:email].downcase)
    if @user # if user exists
      @user.create_reset_digest # sets password reset attributes
      @user.send_password_reset_email # sends the reset email
      flash[:info] = 'Email sent with password reset instructions.'
      redirect_to root_url
    else
      flash.now[:danger] = 'Email address not found'
      render 'new'
    end
  end

  private

  def get_user
    @user = User.find_by(email: params[:email])
  end

  # Confirms a valid user
  def valid_user
    unless (@user && @user.activated? && @user.authenticated?(:reset, params[:id]))
      redirect_to root_url
    end
  end

end
