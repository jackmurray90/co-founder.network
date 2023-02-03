from os.path import join, dirname
def read(filename):
  with open(join(dirname(__file__), filename)) as f:
    return f.read()

strings = {
  'about_optional': 'About (optional)',
  'account_already_exists': "Account already exists with that e-mail address.",
  'agree_terms_1': 'By checking this box you agree to our',
  'agree_terms_2': 'and our',
  'are_you_sure_delete': "Are you sure you want to delete your account?",
  'bump_profile': 'Bump profile to top of list',
  'available_once_per_week': 'Available once per week',
  'city': 'City',
  'city_optional': 'City (optional)',
  'claim_username': 'Claim username',
  'consider_using_cv_network': 'Consider using our sister site <a href="https://cv.network">CV Network</a> to host your CV',
  'cordova_to_login': ' using the device Co-Founder Network is installed on to log in to Co-Founder Network',
  'cordova_to_verify': ' using the device Co-Founder Network is installed on to verify your e-mail address.',
  'members': 'Members',
  'crop': 'Crop',
  'cv': 'CV/LinkedIn',
  'cv_optional': 'CV/LinkedIn (optional)',
  'delete_my_account': "Delete my account.",
  'edit_profile': "Edit profile",
  'email_address': "E-mail Address",
  'email_not_found': "No account with that e-mail address was found.",
  'here': 'here',
  'if_not_signup': 'If you did not sign up to Co-FoundeV Network, please ignore this e-mail.',
  'invalid_username': 'Invalid username. Must contain only lowercase a-z, 0-9, and dash (-) and contain at least one letter.',
  'invalid_email': 'Invalid e-mail address.',
  'message': 'Message',
  'send_connection_request': 'Send connection request',
  'connection_request': 'Connection request',
  'connection_request_sent': "Connection request sent",
  'connected': "Connected",
  'connect': "Connect",
  'connection_email_subject': 'Co-Founder Network connection request from %s',
  'connection_email_header': '%s has sent you a connection request on Co-Founder Network',
  'connection_email_content': "<p>Send them a message by replying to this e-mail to accept the connection request.</p><p>Here is their message:</p>",
  'connection_email_unsubscribe': 'To unsubscribe visit the Settings page on <a href="https://co-founder.network/pages/login">Co-Founder Network</a>.',
  'share_email_warning': 'This will share your email address with',
  'close': "Close",
  'is_taken': ' is taken.',
  'login': "Log In",
  'login_code_expired': 'Login link expired. Please try logging in again.',
  'login_email_header': 'Log In to Co-Founder Network',
  'login_email_sent': "Log in e-mail sent, please check your e-mail for the link to log in.",
  'login_email_subject': "Log In to Co-Founder Network",
  'logout': "Logout",
  'must_agree': 'You must agree to our Terms and Conditions and Privacy Policy before signing up.',
  'name': 'Name',
  'no_get_me_out': "No, I want to keep my account.",
  'open_to_connections': 'Open to connection requests',
  'picture_too_large': 'Image too large. Max size 2MB.',
  'please_click': "Please click ",
  'privacy': read('privacy.html'),
  'privacy_policy': 'Privacy Policy',
  'profile_picture': 'Profile picture',
  'receive_connection_emails': 'Receive connection request emails',
  'referrers': "Referrers",
  'save_changes': 'Save changes',
  'show_email': 'Show e-mail address on profile',
  'show_profile': 'Profile page is visible to public',
  'sign_up': "Sign up",
  'successful_claim': 'Successfully claimed username ',
  'terms': read('terms.html'),
  'terms_and_conditions': 'Terms and Conditions',
  'to_login': ' to log in to Co-Founder Network',
  'to_verify': ' to verify your e-mail address.',
  'url_optional': 'URL (optional)',
  'username': 'Username',
  'verification_email_header': 'Welcome to Co-Founder Network',
  'verification_email_subject': 'Verify your e-mail.',
  'verify_your_email': 'Please verify your e-mail by clicking the link we sent to %s.',
  'settings': 'Settings',
  'yes_delete': "Yes, delete my account",
  'your_name_here': "<Your Name Here>"
}
