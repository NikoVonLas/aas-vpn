import ru from '/assets/vendor/intl-tel-input/29.2.3/js/locale/ru.js';

// The widget formats telephone fields; forms keep their normal POST action.
for (const input of document.querySelectorAll('input[type=tel]')) {
  if (input.readOnly || input.disabled) continue;
  const phone = window.intlTelInput(input, {
    initialCountry: 'ru', countryNameLocale: 'ru', uiTranslations: ru,
    countrySelectorMode: 'DROPDOWN', dropdownParent: document.body,
    numberDisplayFormat: 'NATIONAL', separateDialCode: true, strictMode: false,
    allowedNumberTypes: null,
  });
  const clearError = () => input.setCustomValidity('');
  input.addEventListener('input', clearError);
  input.addEventListener('countrychange', clearError);
  input.addEventListener('change', () => {
    clearError();
    // Includes restored drafts and browser autofill.
    phone.setNumber(input.value);
  });
  input.form?.addEventListener('submit', event => {
    if (event.submitter?.formNoValidate || !input.value.trim()) return;
    if (phone.isValidNumber() === false) {
      input.setCustomValidity('Проверьте номер телефона и выбранную страну');
      event.preventDefault();
      input.reportValidity();
    }
  }, true);
  input.form?.addEventListener('formdata', event => {
    if (input.name && !input.disabled && input.value.trim()) {
      event.formData.set(input.name, phone.getNumber('E164') || input.value);
    }
  });
}
