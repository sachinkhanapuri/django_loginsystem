# from django.contrib.auth.tokens import PasswordResetTokenGenerator
# from six import text_type
#
# class TokenGenerator(PasswordResetTokenGenerator):
#     def _make_hash_value(self, user_id, timestamp):
#         print("username:",user_id)
#         #login_timestamp = '' if user_id.last_login is None else user_id.last_login.replace(microsecond=0, tzinfo=None)
#         return(
#                 text_type(user_id) + user_id.password
#                 #text_type(login_timestamp) + text_type(timestamp)
#         )
#
# generate_token = TokenGenerator()