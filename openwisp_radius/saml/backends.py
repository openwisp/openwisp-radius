from djangosaml2.backends import Saml2Backend

from .. import settings as app_settings


class OpenwispRadiusSaml2Backend(Saml2Backend):
    def _update_user(self, user, attributes, attribute_mapping, force_save=False):
        if (
            not app_settings.SAML_UPDATES_PRE_EXISTING_USERNAME
            and not user._state.adding
        ):
            # Skip updating user's username if the user didn't signed up
            # with SAML registration method.
            attribute_mapping = attribute_mapping.copy()
            # Check if any of the user's registered_users records
            # were NOT created via SAML.
            # NOTE: This uses a global check (any org) rather than org-specific.
            # This is intentionally conservative: if a user has ever signed up
            # via a non-SAML method in any org, their username won't be updated
            # during SAML login in any org. This prevents the SAML identity
            # provider from overwriting a username set or preferred by the user
            # elsewhere. Since the User model is shared across organizations,
            # updating the username based solely on one org's SAML flow could
            # unexpectedly change the user's identity in other orgs.
            has_non_saml = user.registered_users.exclude(method="saml").exists()
            if has_non_saml:
                for key, value in attribute_mapping.items():
                    if "username" in value:
                        break
                if len(value) == 1:
                    attribute_mapping.pop(key, None)
                else:
                    attribute_mapping[key] = []
                    for attr in value:
                        if attr != "username":
                            attribute_mapping[key].append(attr)
        return super()._update_user(user, attributes, attribute_mapping, force_save)
