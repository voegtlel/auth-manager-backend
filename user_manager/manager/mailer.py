import os
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Tuple

from mako.lookup import TemplateLookup

from user_manager.common.config import config


class Mailer:
    def __init__(self):
        self.template_lookup = TemplateLookup(directories=[os.path.join(os.path.dirname(__file__), 'mail_templates')])

    def connect(self) -> smtplib.SMTP:
        if config.manager.mail.ssl:
            port = 465
        elif config.manager.mail.starttls:
            port = 587
        else:
            port = 25
        if config.manager.mail.port is not None:
            port = config.manager.mail.port

        if config.manager.mail.ssl:
            keyfile = config.manager.mail.keyfile
            certfile = config.manager.mail.certfile
            context = ssl.create_default_context() if not keyfile and not certfile else None
            mailer = smtplib.SMTP_SSL(
                config.manager.mail.host, port, keyfile=keyfile, certfile=certfile, context=context
            )
        else:
            mailer = smtplib.SMTP(config.manager.mail.host, port)
        try:
            if config.manager.mail.starttls:
                keyfile = config.manager.mail.keyfile
                certfile = config.manager.mail.certfile
                context = ssl.create_default_context() if not keyfile and not certfile else None
                mailer.starttls(keyfile=keyfile, certfile=certfile, context=context)

            if config.manager.mail.user and config.manager.mail.password:
                mailer.login(config.manager.mail.user, config.manager.mail.password)
        except BaseException:
            mailer.close()
            raise
        return mailer

    def _render_template(self, language: str, name: str, **kwargs) -> Tuple[str, str]:
        if language != 'en_us' and not self.template_lookup.has_template(f'{language}/{name}'):
            language = 'en_us'

        template = self.template_lookup.get_template(f'{language}/{name}')
        data = template.render(
            config=config,
            **kwargs,
        )
        return data.split('\n', 1)

    def send_mail(self, language: str, name: str, to: str, context: dict):
        html_title, html_data = self._render_template(language, name + '.html', **context)
        txt_title, txt_data = self._render_template(language, name + '.txt', **context)
        assert txt_title == html_title

        message = MIMEMultipart('alternative')
        message['Subject'] = txt_title
        message.attach(MIMEText(html_data, 'html'))
        message.attach(MIMEText(txt_data, 'plain'))

        with self.connect() as connected_mailer:
            connected_mailer.sendmail(config.manager.mail.sender, [to], message.as_bytes())


mailer = Mailer()
