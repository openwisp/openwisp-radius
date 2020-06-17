from openwisp_users.tests.test_admin import TestBasicUsersIntegration

from .mixins import GetEditFormInlineMixin


class TestUsersIntegration(GetEditFormInlineMixin, TestBasicUsersIntegration):
    """
    tests integration with openwisp_users
    """

    pass


del TestBasicUsersIntegration
