(function ($) {
    'use strict';
    $(document).ready(function () {
        $('#id_radius_settings-0-sms_verification').on('change', function () {
            var smsVerificationEnabled = $(this).val(),
                smsOptions = $('.org-sms-options:visible .form-row:not(.field-sms_verification)');
            if (smsVerificationEnabled === '') {
                smsVerificationEnabled = $(this).data('default-value');
            }
            switch (smsVerificationEnabled) {
            case 'True':
                smsOptions.show();
                break;
            case 'False':
                smsOptions.hide();
                break;
            }
        });
        $('#id_radius_settings-0-sms_verification').trigger('change');
    });
}(django.jQuery));
