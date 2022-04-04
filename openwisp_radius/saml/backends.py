from django.core.exceptions import ObjectDoesNotExist
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
            try:
                attribute_mapping = attribute_mapping.copy()
                if user.registered_user.method != 'saml':
                    for key, value in attribute_mapping.items():
                        if 'username' in value:
                            break
                    if len(value) == 1:
                        attribute_mapping.pop(key, None)
                    else:
                        attribute_mapping[key] = []
                        for attr in value:
                            if attr != 'username':
                                attribute_mapping[key].append(attr)

            except ObjectDoesNotExist:
                pass
        return super()._update_user(user, attributes, attribute_mapping, force_save)
