import base64

from django.conf import settings
from django.utils.module_loading import import_string
from djangosaml2.cache import OutstandingQueriesCache


class TestSamlMixins:
    """
    This class contains contains methods copied from djangosaml2.tests.SAML2Tests.
    """

    def b64_for_post(self, xml_text, encoding='utf-8'):
        return base64.b64encode(xml_text.encode(encoding)).decode('ascii')

    def add_outstanding_query(self, session_id, came_from):
        settings.SESSION_ENGINE = 'django.contrib.sessions.backends.db'
        engine = import_string(settings.SESSION_ENGINE)
        self.saml_session = engine.SessionStore()
        self.saml_session.save()
        self.oq_cache = OutstandingQueriesCache(self.saml_session)

        self.oq_cache.set(
            session_id if isinstance(session_id, str) else session_id.decode(),
            came_from,
        )
        self.saml_session.save()
        self.client.cookies[
            settings.SESSION_COOKIE_NAME
        ] = self.saml_session.session_key
