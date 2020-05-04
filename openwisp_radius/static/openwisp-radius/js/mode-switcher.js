(function ($) {
    'use strict';
    $(document).ready(function () {
        var mode = $('#id_mode'),
            allExceptMode = $('.form-row:not(.field-mode)'),
            neutral = $('.form-row:not(.field-group, .field-groupname, ' +
                        '.field-user, .field-username)'),
            guided = $('.field-group, .field-user'),
            custom = $('.field-groupname, .field-username');
        mode.change(function (e) {
            allExceptMode.hide();
            if (mode.val() === 'guided') {
                guided.show();
                neutral.show();
                $('#id_groupname').val('');
                $('#id_username').val('');
            } else if (mode.val() === 'custom') {
                custom.show();
                neutral.show();
                $('#id_group').val(null).change();
                $('#id_user').val(null).change();
            }
        });
        if ($('#id_group').val() || $('#id_user').val()) {
            mode.val('guided');
        } else if ($('#id_groupname').val() || $('#id_username').val()) {
            mode.val('custom');
        }
        mode.trigger('change');
    });
}(django.jQuery));
