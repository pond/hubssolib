/************************************************************************\
 * File:    confirm_button.js                                           *
 *          Hipposoft 2025                                              *
 *                                                                      *
 * Purpose: A very simple confirm prompt that hooks into any anchor or  *
 *          in-form button with "data-confirm: foo" specified. Visits   *
 *          the anchor HREF or submits the containing form (which must  *
 *          be an immediate parent node of the button) on confirmation. *
 *                                                                      *
 * History: 15-Jan-2025 (ADH): Created.                                 *
\************************************************************************/

function confirmClick(element) {
  element.addEventListener('click', function(event) {
    event.preventDefault();
    event.stopPropagation();

    const proceed = window.confirm(element.dataset.confirm);

    if (proceed) {
      if (element.href) {
        window.location.href = element.href;
      } else {
        const presumedFormElement = element.parentNode;
        presumedFormElement.submit();
      }
    };
  });
}

document.addEventListener('DOMContentLoaded', function(event) {
  const confirmationElements = document.querySelectorAll('[data-confirm]');

  confirmationElements.forEach(function(confirmationElement, confirmationElementIndex, listObject) {
    confirmClick(confirmationElement);
  });
});
