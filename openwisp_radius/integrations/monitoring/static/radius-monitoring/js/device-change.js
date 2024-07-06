(function ($) {
    'use strict';

    const onlineMsg = gettext('online');

    $(document).ready(function () {
        if (!$('#radius-sessions').length) {
            // RADIUS sessions tab should not appear on Device add page.
            return;
        }
        // Move the "RADIUS Sessions" tab after the "Credentials" tab.
        $('ul.tabs li.credentials').after($('ul.tabs li.radius-sessions'));

        const deviceMac = encodeURIComponent($('#id_mac_address').val()),
            apiEndpoint = `${radiusAccountingApiEndpoint}?called_station_id=${deviceMac}`;

        function getFormattedDateTimeString(dateTimeString) {
            // Strip the timezone from the dateTimeString.
            // This is done to show the time in server's timezone
            // because RadiusAccounting admin also shows the time in server's timezone.
            let strippedDateTime = new Date(dateTimeString.replace(/[-+]\d{2}:\d{2}$/, ''));
            return strippedDateTime.toLocaleString();
        }

        function fetchRadiusSessions() {
            if ($('#radius-session-tbody').children().length) {
                // Don't fetch if RADIUS sessions are already present
                // in the table
                return;
            }
            $.ajax({
                type: 'GET',
                url: apiEndpoint,
                xhrFields: {
                    withCredentials: true
                },
                crossDomain: true,
                beforeSend: function() {
                    $('#radius-sessions .loader').show();
                },
                complete: function () {
                    $('#radius-sessions .loader').hide();
                },
                success: function (response) {
                    if (response.length === 0) {
                        $('#no-session-msg').show();
                        return;
                    }
                    // The called_station_id in the response is in the format accepted by
                    // RadiusAccountingAdmin. This ensures that we use the same format for
                    // filtering the RadiusAccountingAdmin table, avoiding any problem with
                    // different formats of MAC address in the backend.
                    let called_station_id = response[0].called_station_id,
                        radiusAccountingAdminUrl = `${radiusAccountingAdminPath}?called_station_id=${encodeURIComponent(called_station_id)}`;
                    $('#view-all-radius-session-wrapper a').attr('href', radiusAccountingAdminUrl);

                    response.forEach((element, index) => {
                        element.start_time = getFormattedDateTimeString(element.start_time);
                        if (!element.stop_time) {
                            element.stop_time = `<strong>${onlineMsg}</strong>`;
                        } else {
                            element.stop_time = getFormattedDateTimeString(element.stop_time);
                        }
                        $('#radius-session-tbody').append(
                            `<tr class="form-row has_original dynamic-radiussession_set" id="radiussession_set-${index}">
                                <td class="original"></td>
                                <td class="field-session_id"><p>${element.session_id}</p></td>
                                <td class="field-username"><p>${element.username}</p></td>
                                <td class="field-input_octets"><p>${element.input_octets}</p></td>
                                <td class="field-output_octets"><p>${element.output_octets}</p></td>
                                <td class="field-calling_station_id"><p>${element.calling_station_id}</p></td>
                                <td class="field-start_time"><p>${element.start_time}</p></td>
                                <td class="field-stop_time"><p>${element.stop_time}</p></td>
                            </tr>`
                        );
                    });
                    $('#no-session-msg').hide();
                    $('#device-radius-sessions-table').show();
                    $('#view-all-radius-session-wrapper').show();
                }
            });
        }
        $(document).on('tabshown', function (e) {
            if (e.tabId === '#radius-sessions') {
                fetchRadiusSessions();
            }
        });
        if (window.location.hash == '#radius-sessions') {
            $.event.trigger({
                type: 'tabshown',
                tabId: window.location.hash,
            });
        }
    });
}(django.jQuery));
