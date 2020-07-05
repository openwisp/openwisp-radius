=========================
Extending openwisp-radius
=========================

One of the core values of the OpenWISP project is `Software Reusability <http://openwisp.io/docs/general/values.html#software-reusability-means-long-term-sustainability>`_,
for this reason *openwisp-radius* provides a set of base classes
which can be imported, extended and reused to create derivative apps.

In order to implement your custom version of *openwisp-radius*,
you need to perform the steps described in this section.

When in doubt, the code in the `test project <https://github.com/openwisp/openwisp-radius/tree/master/tests/openwisp2/>`_ and
the `sample app <https://github.com/openwisp/openwisp-radius/tree/master/tests/openwisp2/sample_radius/>`_
will serve you as source of truth:
just replicate and adapt that code to get a basic derivative of
*openwisp-radius* working.

If you want to add new users fields, please follow the `tutorial to extend the
openwisp-users <https://github.com/openwisp/openwisp-users/blob/master#extend-openwisp-users>`_.
As an example, we have extended *openwisp-users* to *sample_users* app and
added a field ``social_security_number`` in the `sample_users/models.py
<https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_users/models.py>`_.

.. note::
    **Premise**: if you plan on using a customized version of this module,
    we suggest to start with it since the beginning, because migrating your data
    from the default module to your extended version may be time consuming.

1. Initialize your custom module
--------------------------------

The first thing you need to do is to create a new django app which will
contain your custom version of *openwisp-radius*.

A django app is nothing more than a
`python package <https://docs.python.org/3/tutorial/modules.html#packages>`_
(a directory of python scripts), in the following examples we'll call this django app
``myradius``, but you can name it how you want::

    django-admin startapp myradius

Keep in mind that the command mentioned above must be called from a directory
which is available in your `PYTHON_PATH <https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH>`_
so that you can then import the result into your project.

Now you need to add ``myradius`` to ``INSTALLED_APPS`` in your ``settings.py``,
ensuring also that ``openwisp_radius`` has been removed:

.. code-block:: python

    INSTALLED_APPS = [
        # ... other apps ...

        # 'openwisp_radius'  <-- comment out or delete this line
        'myradius'
    ]
.. note::
    For more information about how to work with django projects and django apps, please refer
    to the `django documentation <https://docs.djangoproject.com/en/dev/intro/tutorial01/>`_.

2. Install ``openwisp-radius``
------------------------------

Install (and add to the requirement of your project) openwisp-radius::

    pip install openwisp-radius


3. Add ``EXTENDED_APPS``
------------------------

Add the following to your ``settings.py``:

.. code-block:: python

    EXTENDED_APPS = ('openwisp_radius',)


4. Add ``openwisp_utils.staticfiles.DependencyFinder``
------------------------------------------------------

Add ``openwisp_utils.staticfiles.DependencyFinder`` to
``STATICFILES_FINDERS`` in your ``settings.py``:

.. code-block:: python

    STATICFILES_FINDERS = [
        'django.contrib.staticfiles.finders.FileSystemFinder',
        'django.contrib.staticfiles.finders.AppDirectoriesFinder',
        'openwisp_utils.staticfiles.DependencyFinder',
    ]

5. Add ``openwisp_utils.loaders.DependencyLoader``
--------------------------------------------------

Add ``openwisp_utils.loaders.DependencyLoader`` to ``TEMPLATES`` in your ``settings.py``:

.. code-block:: python

    TEMPLATES = [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'OPTIONS': {
                'loaders': [
                    'django.template.loaders.filesystem.Loader',
                    'django.template.loaders.app_directories.Loader',
                    'openwisp_utils.loaders.DependencyLoader',
                ],
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        }
    ]

6. Inherit the AppConfig class
------------------------------

Please refer to the following files in the sample app of the test project:

- `sample_radius/__init__.py <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/__init__.py>`_
- `sample_radius/apps.py <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/apps.py>`_

You have to replicate and adapt that code in your project.

.. note::
    For more information regarding the concept of ``AppConfig`` please refer to
    the `"Applications" section in the django documentation <https://docs.djangoproject.com/en/dev/ref/applications/>`_.

7. Create your custom models
----------------------------

For the purpose of showing an example, we added a simple ``details`` field to the
`models of the sample app in the test project <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/models.py>`_.

You can add fields in a similar way in your ``models.py`` file.

.. note::
    For doubts regarding how to use, extend or develop models please refer to the
    `"Models" section in the django documentation <https://docs.djangoproject.com/en/dev/topics/db/models/>`_.

8. Add swapper configurations
-----------------------------

Once you have created the models, add the following to your ``settings.py``:

.. code-block:: python

    # Setting models for swapper module
    OPENWISP_RADIUS_RADIUSREPLY_MODEL = 'myradius.RadiusReply'
    OPENWISP_RADIUS_RADIUSGROUPREPLY_MODEL = 'myradius.RadiusGroupReply'
    OPENWISP_RADIUS_RADIUSCHECK_MODEL = 'myradius.RadiusCheck'
    OPENWISP_RADIUS_RADIUSGROUPCHECK_MODEL = 'myradius.RadiusGroupCheck'
    OPENWISP_RADIUS_RADIUSACCOUNTING_MODEL = 'myradius.RadiusAccounting'
    OPENWISP_RADIUS_NAS_MODEL = 'myradius.Nas'
    OPENWISP_RADIUS_RADIUSUSERGROUP_MODEL = 'myradius.RadiusUserGroup'
    OPENWISP_RADIUS_RADIUSPOSTAUTHENTICATION_MODEL = 'myradius.RadiusPostAuth'

Substitute ``myradius`` with the name you chose in step 1.

9. Create database migrations
-----------------------------

Create database migrations::

    ./manage.py makemigrations

Now, manually create a file ``0002_default_groups_and_permissions.py`` in the migrations directory just create by the ``makemigrations`` command and copy contents of the `sample_radius/migrations/0002_default_groups_and_permissions.py <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/migrations/0002_default_groups_and_permissions.py>`_.

Apply database migrations::

    ./manage.py migrate

.. note::
    For more information, refer to the
    `"Migrations" section in the django documentation <https://docs.djangoproject.com/en/dev/topics/migrations/>`_.

10. Create the admin
--------------------

Refer to the `admin.py file of the sample app <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/admin.py>`_.

To introduce changes to the admin, you can do it in two main ways which are described below.

.. note::
    For more information regarding how the django admin works, or how it can be customized, please refer to
    `"The django admin site" section in the django documentation <https://docs.djangoproject.com/en/dev/ref/contrib/admin/>`_.

1. Monkey patching
^^^^^^^^^^^^^^^^^^

If the changes you need to add are relatively small, you can resort to monkey patching.

For example:

.. code-block:: python

    from openwisp_radius.admin import (
        RadiusCheckAdmin,
        RadiusReplyAdmin,
        RadiusAccountingAdmin,
        NasAdmin,
        RadiusGroupAdmin,
        RadiusUserGroupAdmin,
        RadiusGroupCheckAdmin,
        RadiusGroupReplyAdmin,
        RadiusPostAuthAdmin,
        RadiusBatchAdmin,
    )
    # NasAdmin.fields += ['example_field'] <-- Monkey patching changes example

2. Inheriting admin classes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you need to introduce significant changes and/or you don't want to resort to
monkey patching, you can proceed as follows:

.. code-block:: python

    from django.contrib import admin
    from openwisp_radius.admin import (
        RadiusCheckAdmin as BaseRadiusCheckAdmin,
        RadiusReplyAdmin as BaseRadiusReplyAdmin,
        RadiusAccountingAdmin as BaseRadiusAccountingAdmin,
        NasAdmin as BaseNasAdmin,
        RadiusGroupAdmin as BaseRadiusGroupAdmin,
        RadiusUserGroupAdmin as BaseRadiusUserGroupAdmin,
        RadiusGroupCheckAdmin as BaseRadiusGroupCheckAdmin,
        RadiusGroupReplyAdmin as BaseRadiusGroupReplyAdmin,
        RadiusPostAuthAdmin as BaseRadiusPostAuthAdmin,
        RadiusBatchAdmin as BaseRadiusBatchAdmin,
    )
    from swapper import load_model
    Nas = load_model('openwisp_radius', 'Nas')
    RadiusAccounting = load_model('openwisp_radius', 'RadiusAccounting')
    RadiusBatch = load_model('openwisp_radius', 'RadiusBatch')
    RadiusCheck = load_model('openwisp_radius', 'RadiusCheck')
    RadiusGroup = load_model('openwisp_radius', 'RadiusGroup')
    RadiusPostAuth = load_model('openwisp_radius', 'RadiusPostAuth')
    RadiusReply = load_model('openwisp_radius', 'RadiusReply')
    PhoneToken = load_model('openwisp_radius', 'PhoneToken')
    RadiusGroupCheck = load_model('openwisp_radius', 'RadiusGroupCheck')
    RadiusGroupReply = load_model('openwisp_radius', 'RadiusGroupReply')
    RadiusUserGroup = load_model('openwisp_radius', 'RadiusUserGroup')
    OrganizationRadiusSettings = load_model('openwisp_radius', 'OrganizationRadiusSettings')
    User = get_user_model()

    admin.site.unregister(RadiusCheck)
    admin.site.unregister(RadiusReply)
    admin.site.unregister(RadiusAccounting)
    admin.site.unregister(Nas)
    admin.site.unregister(RadiusGroup)
    admin.site.unregister(RadiusUserGroup)
    admin.site.unregister(RadiusGroupCheck)
    admin.site.unregister(RadiusGroupReply)
    admin.site.unregister(RadiusPostAuth)
    admin.site.unregister(RadiusBatch)

    @admin.register(RadiusCheck)
    class RadiusCheckAdmin(BaseRadiusCheckAdmin):
        # add your changes here

    @admin.register(RadiusReply)
    class RadiusReplyAdmin(BaseRadiusReplyAdmin):
        # add your changes here

    @admin.register(RadiusAccounting)
    class RadiusAccountingAdmin(BaseRadiusAccountingAdmin):
        # add your changes here

    @admin.register(Nas)
    class NasAdmin(BaseNasAdmin):
        # add your changes here

    @admin.register(RadiusGroup)
    class RadiusGroupAdmin(BaseRadiusGroupAdmin):
        # add your changes here

    @admin.register(RadiusUserGroup)
    class RadiusUserGroupAdmin(BaseRadiusUserGroupAdmin):
        # add your changes here

    @admin.register(RadiusGroupCheck)
    class RadiusGroupCheckAdmin(BaseRadiusGroupCheckAdmin):
        # add your changes here

    @admin.register(RadiusGroupReply)
    class RadiusGroupReplyAdmin(BaseRadiusGroupReplyAdmin):
        # add your changes here

    @admin.register(RadiusPostAuth)
    class RadiusPostAuthAdmin(BaseRadiusPostAuthAdmin):
        # add your changes here

    @admin.register(RadiusBatch)
    class RadiusBatchAdmin(BaseRadiusBatchAdmin):
        # add your changes here

11. Create root URL configuration
---------------------------------

.. code-block:: python

    from openwisp_radius.urls import get_urls
    # Only imported when views are extended.
    # from .sample_radius.api.views import views as api_views
    # from .sample_radius.social.views import views as social_views

    urlpatterns = [
        # ... other urls in your project ...
        path('admin/', admin.site.urls),
        # openwisp-radius urls
        path('accounts/', include('openwisp_users.accounts.urls')),
        path('', include('openwisp_radius.urls')),
        # Use only when extending views (dicussed below)
        # path('', include((get_urls(api_views, social_views), 'radius'), namespace='radius')),
        path('', include((get_urls(), 'radius'), namespace='radius',)), # Remove when extending views
    ]
.. note::
    For more information about URL configuration in django, please refer to the
    `"URL dispatcher" section in the django documentation <https://docs.djangoproject.com/en/dev/topics/http/urls/>`_.

12. Import the automated tests
------------------------------

When developing a custom application based on this module, it's a good
idea to import and run the base tests too, so that you can be sure the changes
you're introducing are not breaking some of the existing features of *openwisp-radius*.

In case you need to add breaking changes, you can overwrite the tests defined
in the base classes to test your own behavior.

See the `tests of the sample app <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/tests.py>`_
to find out how to do this.

You can then run tests with::

    # the --parallel flag is optional
    ./manage.py test --parallel myradius

Substitute ``myradius`` with the name you chose in step 1.

Other base classes that can be inherited and extended
-----------------------------------------------------

The following steps are not required and are intended for more advanced customization.

1. Extending the API Views
^^^^^^^^^^^^^^^^^^^^^^^^^^

The API view classes can be extended into other django applications as well. Note
that it is not required for extending *openwisp-radius* to your app and this change
is required only if you plan to make changes to the API views.

Create a view file as done in `API views.py <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/api/views.py>`_.

Remember to use these views in root URL configurations in point 11.
If you want only extend the API views and not social views, you can use
``get_urls(api_views, None)`` to get social_views from *openwisp_radius*.

.. note::
    For more information about django views, please refer to the
    `views section in the django documentation <https://docs.djangoproject.com/en/dev/topics/http/views/>`_.


2. Extending the Social Views
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The social view classes can be extended into other django applications as well. Note
that it is not required for extending *openwisp-radius* to your app and this change
is required only if you plan to make changes to the social views.

Create a view file as done in `social views.py <https://github.com/openwisp/openwisp-radius/blob/master/tests/openwisp2/sample_radius/social/views.py>`_.

Remember to use these views in root URL configurations in point 11.
If you want only extend the API views and not social views, you can use
``get_urls(None, social_views)`` to get social_views from *openwisp_radius*.

.. note::
    For more information about django views, please refer to the
    `views section in the django documentation <https://docs.djangoproject.com/en/dev/topics/http/views/>`_.
