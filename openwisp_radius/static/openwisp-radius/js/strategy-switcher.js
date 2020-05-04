(function ($) {
    'use strict';
    $(document).ready(function () {
        var strategy = $('#id_strategy'),
            prefixRows = $('#id_prefix, #id_name, ' +
                           '#id_expiration_date, #id_number_of_users').parents('.form-row'),
            csvRows = $('#id_csvfile, #id_name, ' +
                        '#id_expiration_date').parents('.form-row'),
            prefixField = $('.form-row.field-prefix'),
            pdfField = $('.form-row.field-pdf'),
            csvField = $('.form-row.field-csvfile'),
            strategyField = $('.form-row.field-strategy .readonly')["0"];

        function csv_strategy() {
            prefixRows.hide();
            prefixField.hide();
            pdfField.hide();
            csvRows.show();
            csvField.show();
        }

        function prefix_strategy() {
            csvRows.hide();
            csvField.hide();
            prefixRows.show();
            prefixField.show();
            pdfField.show();
        }

        if (strategyField !== undefined) {
            if (strategyField.innerHTML === "Import from CSV") {
                csv_strategy();
            } else if (strategyField.innerHTML === "Generate from prefix") {
                prefix_strategy();
            }
        }

        strategy.change(function (e) {
            if (strategy.val() === 'prefix') {
                prefix_strategy();
            } else if (strategy.val() === 'csv') {
                csv_strategy();
            } else {
                prefixRows.hide();
                prefixField.hide();
                pdfField.hide();
                csvRows.hide();
                csvField.hide();
            }
        });
        strategy.trigger('change');
    });
}(django.jQuery));
