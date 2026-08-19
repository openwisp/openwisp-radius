(function ($) {
  "use strict";
  $(document).ready(function () {
    var strategy = $("#id_strategy"),
      prefixRows = $(
        "#id_prefix, #id_name, #id_expiration_date, " +
          "#id_number_of_users, #id_group, #id_notes",
      ).parents(".form-row"),
      csvRows = $(
        "#id_csvfile, #id_name, #id_expiration_date, #id_group, #id_notes",
      ).parents(".form-row"),
      prefixField = $(".form-row.field-prefix"),
      pdfField = $(".form-row.field-pdf"),
      csvField = $(".form-row.field-csvfile"),
      groupField = $("#id_group"),
      organizationField = $("#id_organization"),
      strategyField = $(".form-row.field-strategy .readonly")["0"],
      defaultGroupRequest = 0;

    function select_default_group() {
      var organization = organizationField.val(),
        defaultUrl = groupField.attr("data-default-url"),
        request = ++defaultGroupRequest;

      if (!organization || !groupField.length || !defaultUrl) {
        return;
      }
      groupField.val(null).trigger("change");
      $.get(defaultUrl.replace("__organization__", organization)).done(
        function (group) {
          if (
            request !== defaultGroupRequest ||
            organizationField.val() !== organization
          ) {
            return;
          }
          groupField
            .append(new Option(group.text, group.id, true, true))
            .trigger("change");
        },
      );
    }

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

    strategy.change(function () {
      if (strategy.val() === "prefix") {
        prefix_strategy();
      } else if (strategy.val() === "csv") {
        csv_strategy();
      } else {
        prefixRows.hide();
        prefixField.hide();
        pdfField.hide();
        csvRows.hide();
        csvField.hide();
      }
    });
    organizationField.change(select_default_group);
    strategy.trigger("change");
    $(window).on("load", function () {
      select_default_group();
    });
  });
})(django.jQuery);
