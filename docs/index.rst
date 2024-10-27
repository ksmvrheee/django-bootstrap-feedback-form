Description
-----------
This is a Django reusable application for creating a feedback form for users to contact a website (or a web app) owner or administration with a required confirmation of an email address to ensure that the user provides an email they have access to. The form itself is rendered on the page with the template tag while the form usage sessions are stored in the database. The initial validation and the UI manipulations are powered by JavaScript code which communicates with the server side via AJAX. The form includes a bootstrap powered modal which is used to prevent the user from entering obviously incorrect or invalid data or not even trying to confirm their email.

The html component of the form itself is responsive and complies with a various screen sizes.

To protect a server from the unwanted artificial requests that can potentially be made using the form or the app REST-endpoints, the reCaptcha widget is included on the frontend and it's validation is implemented on the backend. Obviously, the user gets some extra attempts to resend a confirmation email message without a necessary reCaptcha reentering, but this action can be done just 2 times before the user would be asked to complete the reCaptcha task again.

Various checks and UI validations are implemented to prevent the submitting of explicitly invalid data to the backend, but of course there is a second layer of the data cleaning. The UI uses pure JS animations to manage a layout and communicates with the user with several defined messages and warnings. The backend and frontend interactions rely on a REST methodology.

The key functions of the app rely on Django email sending feature and imply that a certain email backend is set up.
User is expected to enter the captcha, press a key to request a confirmation email message, enter a received six-digit code, enter a desired message and press the "Send" button. After that, the message from the user is sent to the specified on the backend email address with the return email address inside. The templates for both letters are available for overriding.

Detailed topics:

1. `Installation <installation.rst>`_

2. `Prerequisites <prerequisites.rst>`_

3. `Usage <usage.rst>`_

4. `Customization <customization.rst>`_

5. `Potential Problems and Liabilities <potential_problems_and_liabilities.rst>`_