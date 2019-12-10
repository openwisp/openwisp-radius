from openwisp_users.tests.test_admin import TestBasicUsersIntegration


class TestUsersIntegration(TestBasicUsersIntegration):
    """
    tests integration with openwisp_users
    """
    def _get_edit_form_inline_params(self, user, organization):
        params = super()._get_edit_form_inline_params(user, organization)
        rug = user.radiususergroup_set.first()
        params.update({
            # radius user group inline
            'radiususergroup_set-TOTAL_FORMS': 1,
            'radiususergroup_set-INITIAL_FORMS': 1,
            'radiususergroup_set-MIN_NUM_FORMS': 0,
            'radiususergroup_set-MAX_NUM_FORMS': 1000,
            'radiususergroup_set-0-priority': 1,
            'radiususergroup_set-0-group': str(rug.group.pk),
            'radiususergroup_set-0-id': str(rug.pk),
            'radiususergroup_set-0-user': str(rug.user.pk),
            # social account inline
            'socialaccount_set-TOTAL_FORMS': 0,
            'socialaccount_set-INITIAL_FORMS': 0,
            'socialaccount_set-MIN_NUM_FORMS': 0,
            'socialaccount_set-MAX_NUM_FORMS': 0,
        })
        return params


del TestBasicUsersIntegration
