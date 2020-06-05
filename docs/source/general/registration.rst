=========================
Registration of new users
=========================

openwisp-radius uses `django-rest-auth <https://github.com/Tivix/django-rest-auth>`_
which provides registration of new users via REST API so you can implement
registration and password reset directly from your captive page.

If you want to use another library for the same, please `extend <how_to_extend.html>`_
*openwisp-radius* and simply install your prefered library and write
`custom API views <how_to_extend.html#extending-the-api-views>`_ for it.

The registration API endpoint is described in `API: User Registration <api.html#user-registration>`_
