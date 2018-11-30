from openwisp_radius.tests.test_users_integration import TestUsersIntegration as BaseTestUsersIntegration


class TestUsersIntegration(BaseTestUsersIntegration):
    """
    tests integration with openwisp_users
    """
    def _get_edit_form_inline_params(self, user, organization):
        params = super()._get_edit_form_inline_params(user, organization)
        params.update({
            # userplan inline
            'userplan-TOTAL_FORMS': 0,
            'userplan-INITIAL_FORMS': 0,
            'userplan-MIN_NUM_FORMS': 0,
            'userplan-MAX_NUM_FORMS': 0,
            # billing info inline
            'billinginfo-TOTAL_FORMS': 0,
            'billinginfo-INITIAL_FORMS': 0,
            'billinginfo-MIN_NUM_FORMS': 0,
            'billinginfo-MAX_NUM_FORMS': 0,
        })
        return params


del BaseTestUsersIntegration
