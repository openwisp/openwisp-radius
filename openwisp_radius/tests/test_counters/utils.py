_acct_data = {
    'username': 'tester',
    'session_id': '1',
    'unique_id': '1',
    'nas_ip_address': '127.0.0.1',
    'realm': '',
    'nas_port_id': '1',
    'nas_port_type': 'Async',
    'session_time': '250',
    'authentication': 'RADIUS',
    'input_octets': '1000',
    'output_octets': '2000',
    'called_station_id': '00-27-22-F3-FA-F1:hostname',
    'calling_station_id': '5c:7d:c1:72:a7:3b',
    'terminate_cause': 'User-Request',
    'service_type': 'Login-User',
    'framed_protocol': 'test',
    'framed_ip_address': '127.0.0.1',
    'framed_ipv6_address': '::1',
    'framed_ipv6_prefix': '0::/64',
    'framed_interface_id': '0000:0000:0000:0001',
    'delegated_ipv6_prefix': '0::/64',
}


class TestCounterMixin:
    def _get_kwargs(self, check_name):
        user = self._get_org_user().user
        group = user.radiususergroup_set.first().group
        group_check = group.radiusgroupcheck_set.filter(attribute=check_name).first()
        return {'user': user, 'group': group, 'group_check': group_check}
