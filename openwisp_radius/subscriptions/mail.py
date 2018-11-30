import logging

from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import EmailMessage
from django.template import loader
from django.utils import translation

email_logger = logging.getLogger('emails')


def send_template_email(recipients, title_template, body_template, context,
                        language, attachments=None):
    """Sends e-mail using templating system"""
    send_emails = getattr(settings, 'SEND_PLANS_EMAILS', True)
    if not send_emails:
        return
    site_name = getattr(settings, 'SITE_NAME', None)
    domain = getattr(settings, 'SITE_URL', None)
    if domain is None:
        try:
            Site = apps.get_model('sites', 'Site')
            current_site = Site.objects.get_current()
            site_name = current_site.name
            domain = current_site.domain
        except LookupError:
            pass
    context.update({'site_name': site_name, 'site_domain': domain})
    if language is not None:
        translation.activate(language)
    mail_title_template = loader.get_template(title_template)
    mail_body_template = loader.get_template(body_template)
    title = mail_title_template.render(context) \
                               .replace('\n', '')  # remove accidental new lines
    body = mail_body_template.render(context)
    try:
        email_from = getattr(settings, 'DEFAULT_FROM_EMAIL')
    except AttributeError:
        raise ImproperlyConfigured('DEFAULT_FROM_EMAIL setting needed for sending e-mails')
    email = EmailMessage(title, body, email_from, recipients)
    attachments = attachments or []
    for attachment in attachments:
        email.attach(*attachment)
    email.send()
    if language is not None:
        translation.deactivate()
    email_logger.info(u"Email (%s) sent to %s\nTitle: %s\n%s\n\n" % (language, recipients, title, body))
