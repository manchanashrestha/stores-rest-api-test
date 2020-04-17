from werkzeug.security import safe_str_cmp
from models.user import UserModel


def authentication(username, password):
    """
    Function that gets called when user calls the /auth endpoint
    with their username and password.
    :param username: User's username in string format
    :param password: USer's un-encrypted password in string format
    :return: A USerModel object if authentication was successful, None otherwise.
    """

    user = UserModel.find_by_username(username)
    if user and safe_str_cmp(user.password, password):
        return user


def identity(payload):
    """
    Function that gets called when user has already authenticated, and Flask-JWT
    verified their authorization header is correct.
    :param payload: A dictionary with 'itentity' key, which is the user id.
    :return: A UserModel object.
    """
    user_id = payload['identity']
    return UserModel.find_by_id(user_id)
