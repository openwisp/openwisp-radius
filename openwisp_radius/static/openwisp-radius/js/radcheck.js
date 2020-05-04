django.jQuery(function ($) {
    'use strict';
    // stop here if in add mode
    if (!('.deletelink').length) { return; }
    if (!gettext) { gettext = function (text) { return text; }; }
    var newValueRow = $('.field-new_value'),
        rawValueRow = $('.field-value'),
        newValueInput = newValueRow.find('input'),
        changeId = 'change-radcheck-value',
        changeHtml = '<button class="button" id="' + changeId + '">' + gettext('change') + '</button>',
        cancelId = 'cancel-change-radcheck-value',
        cancelHtml = '<button class="button" id="' + cancelId + '">' + gettext('cancel') + '</button>';
    if (rawValueRow.find('.readonly').text() !== '') {
        newValueRow.hide();
        rawValueRow.find('.readonly').append(changeHtml);
        newValueInput.after(cancelHtml);
    }
    // change value operation
    $('#' + changeId).click(function (e) {
        e.preventDefault();
        rawValueRow.hide();
        newValueRow.show();
    });
    // cancel change value operation
    $('#' + cancelId).click(function (e) {
        e.preventDefault();
        newValueInput.val('');
        newValueRow.hide();
        rawValueRow.show();
    });
    var value_field = $("#id_new_value");
    function setValueInputType() {
        var selected_attribute = $('.field-attribute option:selected').text();
        if (selected_attribute === "Max-Daily-Session" ||
                selected_attribute === "Max-All-Session" ||
                selected_attribute === "Max-Daily-Session-Traffic") {
            value_field.prop("type", "text");
        } else {
            value_field.prop("type", "password");
        }
    }
    $("#change-radcheck-value").click(setValueInputType);
    $(".field-attribute").change(setValueInputType);
});
