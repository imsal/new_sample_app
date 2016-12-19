#  rails g integration_test users_signup

require 'test_helper'

class UsersSignupTest < ActionDispatch::IntegrationTest

  test "invalid signup information" do
  get signup_path # visits the signup path using get
  # In order to test the form submittion, we need to issue a POST request to users_path

  #assert_select 'form[action="/signup"]' # checks that form submits to /signup
  assert_no_difference 'User.count' do
    post signup_path, params: { user: { name:  "",
                                       email: "user@invalid",
                                       password:              "foo",
                                       password_confirmation: "bar" } }
  end
  assert_template 'users/new'
  # Test for presence of error fields upon failed sign up
  assert_select 'div#error_explanation'
  assert_select 'div.alert-danger'

  end

  test "valid signup information" do
    get signup_path
    assert_difference 'User.count', 1 do
      post users_path, params: { user: { name: "Example User",
                                          email: "user@example.com",
                                          password: "password",
                                          password_confirmation: "password"}}
    end
    follow_redirect! #follow the redirect after submission, resulting in a rendering of the ’users/show’ template
    assert_template 'users/show'
    assert_select 'div.alert-success'
    assert is_logged_in?
  end

end
