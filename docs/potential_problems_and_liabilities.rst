Potential Problems and Liabilities
----------------------------------
There are few problems and legal liabilities associated with using this application.

1. It **uses cookies**. If you must make some notification to the user according to the laws in your jurisdiction, you should probably do it. Although these cookies pretty much should be considered strictly necessary and technical ones: they are used to identify a user and to prevent malfunction (and not in any form to spy or to collect some sensitive data), in some countries they still need to be stated.

2. It **stores user data** in the database. The session identifier, the email address and even the confirmation code are hashed. Although they are hashed by sha256.

3. It **sends a user data** (especially an email address) **over the SMTP protocol (or any other mean that you configure)**. This also may need some notice or something like that. Anyway, use only trusted SMTP providers.

4. If you use the ``mail_admins`` built-in Django logging handler (or something with a similar functionality), you may accidentally send a sensitive data (like an email or ip address) through the email. The ``@sensitive_variables`` decorator is used for every form-related view here to sanitize the data, but there's no warranty. This is applicable to all Django apps unfortunately.

5. Therefore, if applicable, you may need to establish some *Privacy Policy / Terms of Service* or something like that on your site or app.

6. Also some SMTP services tend to not return an errors even if sending the letter goes wrong. That means that it's impossible to catch the issues of that kind on the backend (or at least it is not optimal to do so). But it mainly affects some none-existing email address or host, so it should not affect the full cycle of the form submission (because of the email address confirmation feature), so it's probably fine. Probably.

Anyway, good luck using this app ;)
File an issue on github if something goes wrong.
