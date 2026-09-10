'use strict';
const emailForm = document.getElementById('email-link');
emailForm.elements.proof.value = location.hash.slice(1);
history.replaceState(null, '', location.pathname);
