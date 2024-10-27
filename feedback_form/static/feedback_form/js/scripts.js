// i feel like this code is an atrocity, but i am no js programmer
// nor even a frontend developer so this is the best i can do (:

// elements retrieval
const codeFieldGroup = document.getElementById('codeFieldGroup');
const codeFieldGroupErrorMsg = document.getElementById('codeFieldGroupErrorMessage');
const codeFieldGroupValidationCounter = document.getElementById('codeFieldGroupValidationCounter');
const codeErrors = document.getElementById('codeErrors');
const codeInput = document.getElementById('id_code');
const confirmEmailButton = document.getElementById('confirmEmailButton');
const csrfInput = document.querySelector('input[name="csrfmiddlewaretoken"]');
const emailConfirmationGroup = document.getElementById('emailConfirmationGroup');
const emailConfirmationGroupErrorMsg = document.getElementById('emailConfirmationGroupErrorMessage');
const emailErrors = document.getElementById('emailErrors');
const emailInput = document.getElementById('id_email');
const errorModal = document.getElementById('errorModal');
const emailResendSection = document.getElementById('emailResendSection');
const feedbackForm = document.getElementById('feedbackForm');
const feedbackFormSection = document.getElementById('feedbackFormSection');
const generalErrorMsg = document.getElementById('generalErrorMessage');
const generalFormErrors = document.getElementById('generalFormErrors');
const generalInfoMsg = document.getElementById('generalInfoMessage');
const messageErrors = document.getElementById('messageErrors');
const modalErrorListContainer = document.getElementById('modalErrorListContainer');
const submitFormButton = document.getElementById('submitFormButton');
const textMessageInput = document.getElementById('id_message');

const errorElements = [
  codeErrors,
  codeFieldGroupErrorMsg,
  codeFieldGroupValidationCounter,
  emailConfirmationGroupErrorMsg,
  emailErrors,
  generalErrorMsg,
  generalFormErrors,
  messageErrors
];

// hiding all displayable errors except the specified ones
async function removeErrors({ except = [] } = {}) {
  if (!Array.isArray(except)) {
    except = [except];
  }
  
  await Promise.all(errorElements.map(async function(element) {
    if (!except.includes(element)) {
      await hideElementWithAnimation(element);
    }
  }));
}

// displaying feedback form related errors
async function displayFormErrors(errors) {
  emailErrors.innerHTML = '';
  codeErrors.innerHTML = '';
  messageErrors.innerHTML = '';
  generalFormErrors.innerHTML = '';
  
  let tasks = [];
  
  for (let field in errors) {
    if (errors.hasOwnProperty(field)) {
      let errorMessages = errors[field];
      
      if (field === 'email') {
        errorMessages.forEach(function(message) {
          let errorParagraph = document.createElement('p');
          errorParagraph.className = 'error';
          errorParagraph.innerText = message;
          emailErrors.appendChild(errorParagraph);
        });
        tasks.push(showElementWithAnimation(emailErrors));
      } else if (field === 'code') {
        errorMessages.forEach(function(message) {
          let errorParagraph = document.createElement('p');
          errorParagraph.className = 'error';
          errorParagraph.innerText = message;
          codeErrors.appendChild(errorParagraph);
        });
        tasks.push(showElementWithAnimation(codeErrors));
      } else if (field === 'message') {
        errorMessages.forEach(function(message) {
          let errorParagraph = document.createElement('p');
          errorParagraph.className = 'error';
          errorParagraph.innerText = message;
          messageErrors.appendChild(errorParagraph);
        });
        tasks.push(showElementWithAnimation(messageErrors));
      } else if (field === '__all__') {
        errorMessages.forEach(function(message) {
          let errorParagraph = document.createElement('p');
          errorParagraph.className = 'error';
          errorParagraph.innerText = message;
          generalFormErrors.appendChild(errorParagraph);
        });
        tasks.push(showElementWithAnimation(generalFormErrors));
      }
    }
  }
  
  await Promise.all(tasks);
}

// getting the csrf-cookie
function getCSRFToken() {
  var csrfCookie = document.cookie.match('(^|;)\\s*csrftoken\\s*=\\s*([^;]+)');
  return csrfCookie ? csrfCookie.pop() : '';
}

// checking if reCaptcha is filled
function isCaptchaFilled() {
  return grecaptcha.getResponse().length !== 0;
}

// the callback function for a filled reCaptcha
async function captchaFilled() {
  if (!emailConfirmationGroupErrorMsg.classList.contains('d-none')) {
    await hideElementWithAnimation(emailConfirmationGroupErrorMsg);
    emailConfirmationGroupErrorMsg.textContent = null;
  }
}

// showing element with smooth animation
function showElementWithAnimation(element) {
  return new Promise((resolve, reject) => {
    element.style.transition = 'opacity 0.3s ease-in';
    element.classList.remove('d-none');
    element.style.opacity = '0';
    setTimeout(function() {
      element.style.opacity = '1';
      resolve();
    }, 300);
  });
}

// hiding element with smooth animation
function hideElementWithAnimation(element) {
  return new Promise((resolve, reject) => {
    element.style.transition = 'opacity 0.6s ease';
    element.style.opacity = '0';
    setTimeout(function() {
      element.classList.add('d-none');
      resolve();
    }, 600);
  });
}

// a regular expression for verifying the email input
const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

// checking if the inputted email address passes the regex check
function isEmailInputCorrect() {
  var emailValue = emailInput.value.trim();
  return emailRegex.test(emailValue);
}

// debouncing for avoiding an unwanted functions concurrency
function debounce(func, delay) {
  let timeoutId;
  return function(...args) {
    if (timeoutId) clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      func.apply(this, args);
    }, delay);
  };
}

// showing or hiding email confirmation elements depending on the input
const handleEmailInput = debounce(async function() {
  if (!emailPreliminarilyConfirmed) {
    if (isEmailInputCorrect()) {
      if (emailConfirmationGroup.classList.contains('d-none')) {
        await showElementWithAnimation(emailConfirmationGroup);
      }
    } else if (!emailConfirmationGroup.classList.contains('d-none')) {
      await hideElementWithAnimation(emailConfirmationGroup);
    }
  }
}, 600);
emailInput.addEventListener('input', handleEmailInput);

// displaying email confirmation group on reload if needed
window.onload = function () {
  if (isEmailInputCorrect() && emailConfirmationGroup.classList.contains('d-none')) {
    showElementWithAnimation(emailConfirmationGroup);
  }
};

// ensuring that the code is a number
codeInput.oninput = function() {
  this.value = this.value.replace(/[^0-9]/g, '');
};

// timer related variables
var timerInterval;
var wasCodeResent = false;

// starting or restarting the timer
async function startTimer(errorOccured = false) {
  clearInterval(timerInterval);
  
  secondsRemaining = 30;
  
  if (!emailResendSection.classList.contains('d-none')) {
    await hideElementWithAnimation(emailResendSection);
  }
  
  if (emailResendSection.classList.contains('resend-link-button')) {
    emailResendSection.classList.remove('resend-link-button');
    emailResendSection.removeAttribute('role', 'button');
    emailResendSection.removeAttribute('tabindex', '0');
    
    emailResendSection.removeEventListener('click', resendConfirmationEmail);
  }
  
  if (!errorOccured) {
    if (!wasCodeResent) {
      emailResendText = "Didn't receive the code or have you entered an incorrect address? You can resend it in "
    } else {
      emailResendText = "Didn't receive the code again? You can resend it in "
    }
  } else {
    emailResendText = "You can try resending again in "
  }
  
  emailResendSection.textContent = emailResendText + '30 seconds.';
  
  await showElementWithAnimation(emailResendSection);
  
  timerInterval = setInterval(function() {
    secondsRemaining--;
    if (secondsRemaining > 0) {
      if (secondsRemaining != 1) {
        emailResendSection.textContent = emailResendText + secondsRemaining + ' seconds.';
      } else {
        emailResendSection.textContent = emailResendText + secondsRemaining + ' second.';
      }
    } else {
      clearInterval(timerInterval);
      
      emailResendSection.textContent = 'Click to resend.';
      emailResendSection.classList.add('resend-link-button');
      emailResendSection.setAttribute('role', 'button');
      emailResendSection.setAttribute('tabindex', '0');
      
      emailResendSection.addEventListener('click', resendConfirmationEmail);
    }
  }, 1000);
}

// disabling and removing the timer
async function clearTimer() {
  clearInterval(timerInterval);
  
  if (!emailResendSection.classList.contains('d-none')) {
    await hideElementWithAnimation(emailResendSection);
  }
  
  if (emailResendSection.classList.contains('resend-link-button')) {
    emailResendSection.classList.remove('resend-link-button');
    emailResendSection.removeAttribute('role', 'button');
    emailResendSection.removeAttribute('tabindex', '0');
    
    emailResendSection.removeEventListener('click', resendConfirmationEmail);
  }
  
  emailResendSection.innerHTML = null;
}

// executes all actions from the 'actions' collection of the json content
async function executeActionsFromResponse(jsonResponse) {
  if (jsonResponse.message) {
    generalInfoMsg.textContent = jsonResponse.message;
  }
  
  if (jsonResponse.error) {
    if (jsonResponse.errorScope === 'general') {
      generalErrorMsg.textContent = jsonResponse.error;
    } else if (jsonResponse.errorScope === 'codeField') {
      codeFieldGroupErrorMsg.textContent = jsonResponse.error;
    }
  }
  
  if (jsonResponse.actions) {
    jsonResponse.actions.forEach(async function (actionInstance) {
      if (actionInstance.length > 1) {
        var action = actionInstance[0];
        var target = actionInstance[1];
      } else {
        var action = actionInstance[0];
      }
      
      if (action === 'hide') {
        var element = document.querySelector(target);
        if (element && !element.classList.contains('d-none')) {
          await hideElementWithAnimation(element);
        }
      } else if (action === 'show') {
        var element = document.querySelector(target);
        if (element) {
          await showElementWithAnimation(element);
        }
      } else if (action === 'disable') {
        var element = document.querySelector(target);
        if (element) {
          if ((element != codeInput) || (element != submitFormButton)) {
            element.setAttribute('disabled', '');
          } else {
            element.setAttribute('disabledFinally', '');  // because otherwise it will enable itself :(
          }
        }
      } else if (action === 'enable') {
        if (element) {
          element.removeAttribute('disabled');
        }
      } else if (action === 'resetCaptcha') {
        grecaptcha.reset();
      } else if (action === 'startTimer') {
        startTimer();
      } else if (action === 'startTimerAfterError') {
        startTimer(errorOccured = true);
      } else if (action === 'clearTimer') {
        clearTimer();
        emailPreliminarilyConfirmed = false;
      } else if (action === 'disableInputFields') {
        emailInput.setAttribute('disabled', '');
        codeInput.setAttribute('disabled', '');
        codeInput.setAttribute('disabledFinally', '');
        textMessageInput.setAttribute('disabled', '');
      } else if (action === 'disableButtons') {
        confirmEmailButton.setAttribute('disabled', '');
        submitFormButton.setAttribute('disabled', '');
        submitFormButton.setAttribute('disabledFinally', '');
      }
    });
  }
}

// executing a predetermined set of actions for the 'too many requests' response
async function executeThrottleResponseActions() {
  await removeErrors({ except: generalErrorMsg });
  const unifiedThrottleResponse = {
    'error': 'A limit of requests to the server has been reached. Please try again later.',
    'errorScope': 'general',
    'actions': [ 
      ['hide', '#emailConfirmationGroup'],
      ['hide', '#generalInfoMessage'],
      ['show', '#generalErrorMessage'],
      ['hide', '#codeFieldGroup'],
      ['clearTimer'],
      ['disableInputFields'],
      ['disableButtons']
    ]
  };
  await executeActionsFromResponse(unifiedThrottleResponse);
}

// removes digits from the string (used to execute vigenere encryption)
function removeDigitsFromString(str) {
  return str.replace(/\d/g, '');
}

// length of the random key that will be used to encrypt/mask the tokens
const vigenereKeyLength = 10;

// generating a random secret key for the encryption/masking
function generateRandomKey(length) {
  const characters = 'abcdefghijklmnopqrstuvwxyz';
  let key = '';
  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * characters.length);
    key += characters.charAt(randomIndex);
  }
  return key;
}

// encrypting/masking the string and packing it with the key itself
function vigenereEncrypt(plaintext) {
  let key = generateRandomKey(vigenereKeyLength);
  let ciphertext = '';
  for (let i = 0; i < plaintext.length; i++) {
    const char = plaintext.charAt(i);
    if (char.match(/[a-z]/i)) {
      const keyChar = key.charAt(i % vigenereKeyLength);
      const shift = keyChar.toUpperCase().charCodeAt(0) - 65;
      const charCode = char.charCodeAt(0);
      let encryptedCharCode;
      if (char === char.toLowerCase()) {
        encryptedCharCode = (charCode - 97 + shift) % 26 + 97;
      } else {
        encryptedCharCode = (charCode - 65 + shift) % 26 + 65;
      }
      ciphertext += String.fromCharCode(encryptedCharCode);
    } else {
      ciphertext += char;
    }
  }
  return key + ciphertext;
}

// setting the form session id cookie if it isn't there
function checkAndSetFormSessionCookie() {
  const cookieName = "formsessiontoken";
  
  let cookieValue = removeDigitsFromString(getCSRFToken()).split("").reverse().join("") + generateRandomKey(10);
  
  if (document.cookie.indexOf(cookieName) === -1) {
    document.cookie = cookieName + "=" + cookieValue + "; path=/";
  }
}
document.addEventListener('DOMContentLoaded', checkAndSetFormSessionCookie());

// getting the form session id cookie
function getFormSessionCookie() {
  var cookieName = "formsessiontoken";
  var cookies = document.cookie.split(";");
  for (var i = 0; i < cookies.length; i++) {
    var cookie = cookies[i].trim();
    if (cookie.indexOf(cookieName + "=") === 0) {
      return cookie.substring(cookieName.length + 1, cookie.length);
    }
  }
  return null;
}

// indicates that email was confirmed once to unlock secondary endpoint for reconfirmation (without the captcha)
var emailPreliminarilyConfirmed;

// sending an initial request to verify the email
async function sendConfirmationEmail() {
  if (this.disabled || !emailInput.value || !isEmailInputCorrect()) {
    return;
  }
  
  if (!isCaptchaFilled()) {
    emailConfirmationGroupErrorMsg.textContent = 'Please check the box above (fill in the captcha)';
    await showElementWithAnimation(emailConfirmationGroupErrorMsg);
    return;
  }
  
  this.disabled = true;
  
  if (wasCodeResent) {
    wasCodeResent = false;
  }  
  
  var width = this.offsetWidth + 'px';
  this.style.width = width;
  this.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Sending...';
  
  removeErrors( {except: generalErrorMsg} );
  
  var xhr = new XMLHttpRequest();
  
  xhr.onreadystatechange = async function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
      if (xhr.status == 0) {
        // network error of some sort
        generalErrorMsg.textContent = 'Network error (connection problems, or the server is unavailable)';
        await showElementWithAnimation(generalErrorMsg);
      } else if (xhr.status == 429) {
        await executeThrottleResponseActions();
      } else {
        // working with obtained response
        if (generalErrorMsg.textContent && !generalErrorMsg.classList.contains('d-none')) {
          await hideElementWithAnimation(generalErrorMsg);
          generalErrorMsg.textContent = null;
        }
        
        var contentType = xhr.getResponseHeader('Content-Type');
        if (contentType && contentType.includes('application/json')) {
          var jsonResponse = JSON.parse(xhr.responseText);
          
          if (jsonResponse.success) {
            if (codeInput.hasAttribute('disabled')) {
              codeInput.removeAttribute('disabled');
            }
            
            emailPreliminarilyConfirmed = true;
          }
          
          await executeActionsFromResponse(jsonResponse);
          
          
        } else {
          console.error('Unexpected error: the server returned a response without "application/json" in Content-Type.');
          generalErrorMsg.textContent = 'Unexpected error. Please try again later.';
          showElementWithAnimation(generalErrorMsg);
          if (!generalInfoMsg.classList.contains('d-none')) {
            hideElementWithAnimation(generalInfoMsg);
          }
          if (!codeFieldGroup.classList.contains('d-none')) {
            hideElementWithAnimation(codeFieldGroup);
          }
        }
        
      }
      confirmEmailButton.textContent = 'Confirm email';
      confirmEmailButton.disabled = false;
      confirmEmailButton.style = null;
    }
  };
  
  xhr.open('POST', endpointUrls.emailConfirmationUrl, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  xhr.setRequestHeader('X-CSRFToken', csrfInput.value);
  xhr.setRequestHeader('X-Form-Session-Id', vigenereEncrypt(getFormSessionCookie()));
  
  xhr.send(JSON.stringify({
    'recaptcha-token': grecaptcha.getResponse(),
    'email': emailInput.value
  }));
}
confirmEmailButton.addEventListener('click', sendConfirmationEmail);

// resending a request to verify email
async function resendConfirmationEmail() {
  if (this.disabled) {
    return;
  }
  
  if (!emailInput.value || !isEmailInputCorrect()) {
    generalErrorMsg.textContent = 'Please enter a valid email address';
    await showElementWithAnimation(generalErrorMsg);
    return;
  }
  
  this.disabled = true;
  
  this.classList.add('waiting');
  this.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Sending...';
  
  removeErrors( {except: generalErrorMsg });
  
  var xhr = new XMLHttpRequest();
  
  xhr.onreadystatechange = async function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
      if (xhr.status == 0) {
        // network error of some sort
        generalErrorMsg.textContent = 'Network error (connection problems, or the server is unavailable)';
        await showElementWithAnimation(generalErrorMsg);
      } else if (xhr.status == 429) {
        await executeThrottleResponseActions();
      } else {
        // working with obtained response
        if (generalErrorMsg.textContent && !generalErrorMsg.classList.contains('d-none')) {
          await hideElementWithAnimation(generalErrorMsg);
          generalErrorMsg.textContent = null;
        }
        
        var contentType = xhr.getResponseHeader('Content-Type');
        if (contentType && contentType.includes('application/json')) {
          var jsonResponse = JSON.parse(xhr.responseText);
          
          await executeActionsFromResponse(jsonResponse);
          
          if (jsonResponse.success && !wasCodeResent) {
            wasCodeResent = true;
          }
          
        } else {
          console.error('Unexpected error: the server returned a response without "application/json" in Content-Type.');
          generalErrorMsg.textContent = 'Unexpected error. Please try again later.';
          showElementWithAnimation(generalErrorMsg);
          
          emailPreliminarilyConfirmed = false;
          if (!generalInfoMsg.classList.contains('d-none')) {
            hideElementWithAnimation(generalInfoMsg);
          }
          if (!codeFieldGroup.classList.contains('d-none')) {
            hideElementWithAnimation(codeFieldGroup);
          }
        }
      }
      emailResendSection.innerHTML = null;
      emailResendSection.classList.remove('waiting');
      
      if (!codeFieldGroupErrorMsg.classList.contains('d-none')) {
        hideElementWithAnimation(codeFieldGroupErrorMsg);
      }
      
      emailResendSection.disabled = false;
    }
  };
  
  xhr.open('POST', endpointUrls.emailReconfirmationUrl, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  xhr.setRequestHeader('X-CSRFToken', csrfInput.value);
  xhr.setRequestHeader('X-Form-Session-Id', vigenereEncrypt(getFormSessionCookie()));
  
  xhr.send(JSON.stringify({
    'email': emailInput.value
  }));
}

// attempts to validate code left before user has to resend a new code
var validationAttemptsLeft;

var isCodeConfirmed = false;

// sending the request to validate entered code
async function validateConfirmationCode() {
  if (this.value.length < 6 || this.disabled) {
    return;
  }
  
  this.disabled = true;
  
  removeErrors( {except: [codeFieldGroupErrorMsg, codeFieldGroupValidationCounter] });
  
  var xhr = new XMLHttpRequest();
  
  xhr.onreadystatechange = async function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
      if (xhr.status == 0) {
        // network error of some sort
        codeFieldGroupErrorMsg.textContent = 'Network error (connection problems, or the server is unavailable)';
        await showElementWithAnimation(codeFieldGroupErrorMsg);
      } else if (xhr.status == 429) {
        await executeThrottleResponseActions();
      } else {
        // working with obtained response
        if (codeFieldGroupErrorMsg.textContent && !codeFieldGroupErrorMsg.classList.contains('d-none')) {
          await hideElementWithAnimation(codeFieldGroupErrorMsg);
          codeFieldGroupErrorMsg.textContent = null;
        }
        
        var contentType = xhr.getResponseHeader('Content-Type');
        if (contentType && contentType.includes('application/json')) {
          var jsonResponse = JSON.parse(xhr.responseText);
          
          await executeActionsFromResponse(jsonResponse);
          
          if ('validationAttemptsLeft' in jsonResponse) {
            validationAttemptsLeft = jsonResponse.validationAttemptsLeft;
          }
          
          if (validationAttemptsLeft > 0 && validationAttemptsLeft <= 3) {
            codeFieldGroupValidationCounter.textContent = 'Amount of code entry attempts remaining: ' +  validationAttemptsLeft;
            if (codeFieldGroupValidationCounter.classList.contains('d-none')) {
              showElementWithAnimation(codeFieldGroupValidationCounter);
            }
          } else if (!codeFieldGroupValidationCounter.classList.contains('d-none')) {
            await hideElementWithAnimation(codeFieldGroupValidationCounter);
          }
          
          if (jsonResponse.success) {
            isCodeConfirmed = true;
            // clearTimer();
            var generalErrorsAndWarnings = document.getElementById('generalErrorsAndWarnings');
            if (generalErrorsAndWarnings) {
              await hideElementWithAnimation(generalErrorsAndWarnings);
            }
          } else {
            codeInput.value = null;
          }
          
        } else {
          console.error('Unexpected error: the server returned a response without "application/json" in Content-Type.');
          generalErrorMsg.textContent = 'Unexpected error. Please try again later.';
          showElementWithAnimation(generalErrorMsg);
          
          if (!generalInfoMsg.classList.contains('d-none')) {
            hideElementWithAnimation(generalInfoMsg);
          }
          if (!codeFieldGroup.classList.contains('d-none')) {
            hideElementWithAnimation(codeFieldGroup);
          }
        }
      }
      
      if (!codeInput.hasAttribute('disabledFinally')) {
        codeInput.disabled = false;
      } else {
        codeInput.removeAttribute('disabledFinally');
      }
    }
  };
  
  xhr.open('POST', endpointUrls.codeValidationUrl, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  xhr.setRequestHeader('X-CSRFToken', csrfInput.value);
  xhr.setRequestHeader('X-Form-Session-Id', vigenereEncrypt(getFormSessionCookie()));
  
  xhr.send(JSON.stringify({
    'email': emailInput.value,
    'code': codeInput.value
  }));
}
codeInput.addEventListener('input', validateConfirmationCode);

// regex to check the entered code
const codeInputRegex = /[0-9]+/i;

// creating the modal object for validation errors
const bootstrapErrorModal = new bootstrap.Modal(errorModal);

// displaying an error in the modal if the user tries to hit the submit button without confirming the email
submitFormButton.addEventListener('click', function(event) {
  if (!emailPreliminarilyConfirmed) {
    event.preventDefault();
    
    if (modalErrorListContainer.innerHTML) {
      modalErrorListContainer.innerHTML = null;
    }
    
    var errorElement = document.createElement('p');
    errorElement.textContent = 'First you need to confirm the email address.';
    modalErrorListContainer.appendChild(errorElement);
    
    bootstrapErrorModal.show();
  }
})

// finally submitting the feedback form fields content to the ajax endpoint
async function submitFeedbackForm() {
  if (submitFormButton.disabled) {
    return;
  }
  
  submitFormButton.disabled = true;
  
  var width = submitFormButton.offsetWidth + 'px';
  submitFormButton.style.width = width;
  submitFormButton.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Sending...';
  
  await removeErrors();
  var xhr = new XMLHttpRequest();
  
  xhr.onreadystatechange = async function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
      if (xhr.status == 0) {
        // network error of some sort
        generalFormErrors.textContent = 'Network error (connection problems, or the server is unavailable)';
        await showElementWithAnimation(generalFormErrors);
      } else if (xhr.status == 429) {
        await executeThrottleResponseActions();
      } else {
        // working with obtained response
        var contentType = xhr.getResponseHeader('Content-Type');
        if (contentType && contentType.includes('application/json')) {
          var jsonResponse = JSON.parse(xhr.responseText);
          
          if (!jsonResponse.hasOwnProperty('success')) {
            console.error('Unexpected error: the server returned a response without the neccesary fields.');
            generalFormErrors.textContent = 'A critical error has occurred. Please save your data and try refreshing the page.';
            await showElementWithAnimation(generalFormErrors);
          } else if (!jsonResponse.success) {
            // isCodeConfirmed = false;
            if (jsonResponse.isErrorCritical) {
              emailInput.disabled = false;
              codeInput.value = null;
              codeInput.disabled = true;
              emailPreliminarilyConfirmed = false;
              isCodeConfirmed = false;
              displayFormErrors(jsonResponse.errors);
              await showElementWithAnimation(emailConfirmationGroup);
            } else {
              // codeInput.value = null;
              // codeInput.disabled = false;
              displayFormErrors(jsonResponse.errors);
              // await showElementWithAnimation(codeFieldGroup);
            }
          } else {
            // redirection
            document.cookie = 'form_submitted=1; path=/';
            window.location.replace(endpointUrls.formSuccessUrl);
          }
        } else {
          console.error('Unexpected error: the server returned a response without "application/json" in Content-Type.');
          generalFormErrors.textContent = 'Unexpected error. Please try again later.';
          await showElementWithAnimation(generalFormErrors);
        } 
      }
      submitFormButton.textContent = 'Send';
      if (!submitFormButton.hasAttribute('disabledFinally')) {
        submitFormButton.disabled = false;
      } else {
        submitFormButton.removeAttribute('disabledFinally');
      }
      submitFormButton.style = null;
    }
  };
  
  xhr.open('POST', endpointUrls.formValidationUrl, true);
  xhr.setRequestHeader('Content-Type', 'application/json');
  xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
  xhr.setRequestHeader('X-CSRFToken', csrfInput.value);
  xhr.setRequestHeader('X-Form-Session-Id', vigenereEncrypt(getFormSessionCookie()));
  
  xhr.send(JSON.stringify({
    'email': emailInput.value,
    'code': codeInput.value,
    'message': textMessageInput.value
  }));
};

// displaying validation errors in the modal if there are any
feedbackForm.addEventListener('submit', async function(event) {
  event.preventDefault();
  
  if (modalErrorListContainer.innerHTML) {
    modalErrorListContainer.innerHTML = null;
  }
  
  if (!emailInput.value || !isEmailInputCorrect()) {  // just in case
    var errorElement = document.createElement('p');
    errorElement.textContent = 'Incorrect email address entered.';
    modalErrorListContainer.appendChild(errorElement);
  }
  
  var codeValue = codeInput.value.trim();
  if ((codeValue.length != 6) || !codeInputRegex.test(codeValue) || !isCodeConfirmed) {
    // primary purpose
    var errorElement = document.createElement('p');
    errorElement.textContent = 'Incorrect code entered or no code entered.';
    modalErrorListContainer.appendChild(errorElement);
  }
  
  if (!textMessageInput.value) {  // just in case
    var errorElement = document.createElement('p');
    errorElement.textContent = 'No message entered to send.';
    modalErrorListContainer.appendChild(errorElement);
  }
  
  if (modalErrorListContainer.hasChildNodes()) {
    // showing modal error window
    bootstrapErrorModal.show();
  } else {
    emailInput.disabled = false;
    codeInput.disabled = false;
    await submitFeedbackForm();
  }
});
