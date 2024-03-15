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
            let strippedDateTime = new Date(dateTimeString.substring(0, dateTimeString.lastIndexOf('-'))),
                formattedDate = strippedDateTime.strftime('%d %b %Y, %I:%M %p');
            return formattedDate.replace(/AM/g, 'a.m.').replace(/PM/g, 'p.m.');
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
                    $('#loading-overlay').show();
                },
                complete: function () {
                    $('#loading-overlay').fadeOut(250);
                },
                success: function (response) {
                    if (response.length === 0) {
                        return;
                    }
                    $('#no-session-msg').hide();
                    $('#device-radius-sessions-table').show();
                    $('#view-all-radius-session-wrapper').show();
                    response.forEach(element => {
                        element.start_time = getFormattedDateTimeString(element.start_time);
                        if (!element.stop_time) {
                            element.stop_time = `<strong>${onlineMsg}</strong>`;
                        } else {
                            element.stop_time = getFormattedDateTimeString(element.stop_time);
                        }
                        $('#radius-session-tbody').append(
                            `<tr>
                                <td><p>${element.session_id}</p></td>
                                <td><p>${element.username}</p></td>
                                <td><p>${element.input_octets}</p></td>
                                <td><p>${element.output_octets}</p></td>
                                <td><p>${element.called_station_id}</p></td>
                                <td><p>${element.start_time}</p></td>
                                <td><p>${element.stop_time}</p></td>
                            </tr>`
                        );
                    });
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
        $('#view-all-radius-session-wrapper a').attr('href', `${radiusAccountingAdminPath}?called_station_id=${deviceMac}`);
    });
}(django.jQuery));
