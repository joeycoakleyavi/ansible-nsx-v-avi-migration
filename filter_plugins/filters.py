#!/usr/bin/python
import re
import copy
import ipaddress

class FilterModule(object):
    def __init__(self):
        self.match_pattern = '^acl\s(?P<acl_name>\S+)\s(?P<criterion>\S+)\s(?P<flags>[-ifmnMu]+ )?(?P<value>.*$)'
        self.action_pattern = '^(?P<action>use_backend|redirect location|redirect prefix|block|set-header|add-header)\s+(?P<value>.+)\sif\s(?P<condition>.*)'

        self.rx_dict = {
            'match': re.compile(self.match_pattern),
            'action': re.compile(self.action_pattern)
        }

    def filters(self):
        return {
            'haproxy_to_avi': self.translate_config,
            'parse_ipgroup': self.parse_ipgroup,
            'get_nsx_id': self.get_nsx_id,
            'cipher_string': self.cipher_string
        }

    def cipher_string(self, ciphers):
        cipher_string = ""
        for cipher in ciphers:
            cipher_string += cipher + ":"
        return cipher_string.rstrip(':')

    def parse_ipgroup(self, ipgroup):
        data = {
            'prefixes': [],
            'addrs': [],
            'ranges': []
        }
        for line in ipgroup.splitlines():
            for ipaddr in line.split(","):
                if ipaddr:
                    if "/" in ipaddr:
                        network = ipaddr.split("/")[0]
                        length = ipaddr.split("/")[1]
                        prefix = {
                            "ip_addr": {
                                "addr": network,
                                "type": "V4"
                            },
                            "mask": length
                        }
                        if prefix not in data['prefixes']:
                            data['prefixes'].append(prefix)
                    elif "-" in ipaddr:
                        iprange = {
                            "begin": {
                                "addr": ipaddr.split("-")[0].strip(),
                                "type": "V4"
                            },
                            "end": {
                                "addr": ipaddr.split("-")[1].strip(),
                                "type": "V4"
                            }
                        }
                        if iprange not in data['ranges']:
                            data['ranges'].append(iprange)
                    else:
                        host = {
                            "addr": ipaddr.strip(),
                            "type": "V4"
                        }
                        if host not in data['addrs']:
                            data['addrs'].append(host)
        return data

    def get_nsx_id(self, path):
        try:
            return path.split("/")[-1]
        except Exception as e:
            raise Exception("Unable to parse NSX Id from entry. Ensure the object exists in NSX-T. Path Received: {}".format(path))

    def _lookup_condition(self, condition, matches):
        #Return boolean on whether to translate the match/action if the condition is not handled in policy in Avi
        return True if matches.get(condition, {}).get('unused_criteria') != True else False

    def _parse_line(self, line):
        for key, rx in self.rx_dict.items():
            match = rx.search(line)
            if match:
                return key, match
        return None, None

    def _parse_rules(self, rules):
        data = []
        for rule in rules:
            rule_data = {}
            key, match = self._parse_line(rule['line'])
            if key == 'match':
                acl_name = match.group('acl_name')
                unused_criteria = False
                criterion = match.group('criterion')
                if 'nbsrv' in criterion:
                    unused_criteria = True
                flags = match.group('flags')
                value = match.group('value')
                rule_data = {
                    'line_number': rule['line_number'],
                    'acl_name': acl_name,
                    'criterion': criterion,
                    'flags': flags,
                    'value': value.split(" "),
                    'unused_critera': unused_criteria
                }
                data.append(rule_data)
            elif key == 'action':
                action_name = match.group('action')
                value = match.group('value')
                condition = match.group('condition')
            
                rule_data = {
                    'line_number': rule['line_number'],
                    'action_name': action_name,
                    'value': value.split(" "),
                    'condition': condition.split(" "),
                    'is_inline': False
                }              
                data.append(rule_data)
        return data

    def path_sub(self, value, inverse=False):
        if inverse:
            data = {
                'path': {
                    'match_case': 'INSENSITIVE',
                    'match_criteria': 'DOES_NOT_CONTAIN',
                    'match_str': value
                }
            }
        else:
            data = {
                'path': {
                    'match_case': 'INSENSITIVE',
                    'match_criteria': 'CONTAINS',
                    'match_str': value
                }
            }
        return data

    def path_beg(self, value, inverse=False):
        if inverse:
            data = {
                'path': {
                    'match_case': 'INSENSITIVE',
                    'match_criteria': 'DOES_NOT_BEGIN_WITH',
                    'match_str': value
                }
            }
        else:
            data = {
                'path': {
                    'match_case': 'INSENSITIVE',
                    'match_criteria': 'BEGINS_WITH',
                    'match_str': value
                }
            }
        return data
    
    def hdr_beg(self, value, inverse=False):
        if inverse:
            data = {
                'hdrs': [
                    {
                        'hdr': 'host',
                        'match_case': 'INSENSITIVE',
                        'match_criteria': "HDR_DOES_NOT_BEGIN_WITH",
                        'value': value
                    }
                ]
            }
        else:
            data = {
                'hdrs': [
                    {
                        'hdr': 'host',
                        'match_case': 'INSENSITIVE',
                        'match_criteria': "HDR_BEGINS_WITH",
                        'value': value
                    }
                ]
            }
        return data

    def hdr_dom(self, value, inverse=False):
        if inverse:
            data = {
                'hdrs': [
                    {
                        'hdr': 'host',
                        'match_case': 'INSENSITIVE',
                        'match_criteria': "HDR_DOES_NOT_CONTAIN",
                        'value': value
                    }
                ]
            }
        else:
            data = {
                'hdrs': [
                    {
                        'hdr': 'host',
                        'match_case': 'INSENSITIVE',
                        'match_criteria': "HDR_CONTAINS",
                        'value': value
                    }
                ]
            }
        return data

    def url(self, value, inverse=False):
        data = {
            'path': {
                'match_case': 'INSENSITIVE',
                'match_criteria': 'EQUALS',
                'match_str': value
            }
        }
        return data

    def src(self, value, inverse=False):
        cidrs = [ipaddress.ip_network(value) for value in value]
        cidrs = [(cidr.network_address, cidr.prefixlen) for cidr in cidrs]
        if inverse:
            data = {
                'client_ip': {
                    'match_criteria': 'IS_NOT_IN',
                    'prefixes': [{"ip_addr": {"addr": str(prefix), "type": "V4"}, "mask": mask} for prefix, mask in cidrs]
                }
            }
        else:
            data = {
                'client_ip': {
                    'match_criteria': 'IS_IN',
                    'prefixes': [{"ip_addr": {"addr": str(prefix), "type": "V4"}, "mask": mask} for prefix, mask in cidrs]
                }
            }
        return data

    def is_ssl(self):
        data = {
            "protocol": {
                "match_criteria": "IS_IN",
                "protocols": "HTTPS"
            }
        }
        return data

    def use_backend_poolgroup(self, value):
        data = {
            'switching_action': {
                'action': 'HTTP_SWITCHING_SELECT_POOLGROUP',
                'pool_group_ref': '/api/poolgroup/?name={}'.format(value)
            }
        }

        return data
    
    def redirect_location(self, value):
        #Remove leading /. Avi inserts already
        value = value.lstrip('/')
        data = {
            'redirect_action': {
                'keep_query': False,
                'path': {
                    'tokens': [
                        {
                            'str_value': value,
                            'type': 'URI_TOKEN_TYPE_STRING'
                        }
                    ],
                    'type': 'URI_PARAM_TYPE_TOKENIZED'
                },
                'port': 443,
                'protocol': 'HTTPS',
                'status_code': 'HTTP_REDIRECT_STATUS_CODE_302'
            }
        }

        return data

    def use_backend_pool(self, condition, value):
        pass

    def set_header(self, header_name, value):
        data = {
            'hdr_action': [
                {
                    'action': 'HTTP_ADD_HDR',
                    'hdr': {
                        'name': header_name,
                        'value': {
                            'val': value
                        }
                    }
                }
            ]
        }

        return data

    def translate_config(self, rules):
        parsed_rules = self._parse_rules(rules)
        actions = []
        matches = {}
        name_index = 1

        for rule in parsed_rules:
            if 'acl_name' in rule.keys():
                matches.update({
                    rule['acl_name']: {
                        'criterion': rule['criterion'],
                        'flags': rule['flags'],
                        'unused_criteria': rule['unused_critera'],
                        'value': rule['value']
                    }
                })
            else:
                actions.append(rule)

        result = {'rules': []}

        for action in actions:
            discard_action = False
            data = {
                "enable": True,
                "match": {},
                "index": name_index,
                "name": "rule-{}".format(str(name_index))
            }
            #Build out match parameters
            for condition in action['condition']: #There may be more than one condition to match
                if condition.startswith('!'):
                    inverse_match = True
                    condition = condition.lstrip('!')
                else:
                    inverse_match = False
                if self._lookup_condition(condition, matches):
                    if matches[condition].get('criterion') == 'path_sub':
                        data['match'].update(
                            self.path_sub(matches[condition]['value'], inverse_match)
                        )
                    elif matches[condition].get('criterion') == 'path_beg' or matches[condition].get('criterion') == 'url_beg':
                        if data.get('match', {}).get('path', {}).get('match_str'):
                            data['match']['path']['match_str'].append(matches[condition]['value'])
                        else:
                            data['match'].update(
                                self.path_beg(matches[condition]['value'], inverse_match)
                            )
                    elif matches[condition].get('criterion') == 'url' or matches[condition].get('criterion') == 'path':
                        data['match'].update(
                            self.url(matches[condition]['value'], inverse_match)
                        )
                    elif matches[condition].get('criterion') == 'src':
                        data['match'].update(
                            self.src(matches[condition]['value'], inverse_match)
                        )
                    elif matches[condition].get('criterion') == 'hdr_beg(host)':
                        data['match'].update(
                            self.hdr_beg(matches[condition]['value'], inverse_match)
                        )
                    elif matches[condition].get('criterion') == 'hdr_dom(host)':
                        data['match'].update(
                            self.hdr_dom(matches[condition]['value'], inverse_match)
                        )
                else: 
                    if inverse_match:
                        #Discard the rule. By inverse matching on pooldown, we can ignore this rule.
                        action['condition'].remove('!{}'.format(condition))
                        continue
                    else:
                        #The rule is saying that it applies if unused criteria (pooldown); we skip this action
                        discard_action = True
                        continue
            #A rule should have only one action
            if action['action_name'] == 'use_backend':
                for value in action['value']:
                    data.update(
                        self.use_backend_poolgroup(value)
                    )
                    continue
            elif action['action_name'] == 'redirect location' or action['action_name'] == 'redirect prefix':
                for value in action['value']:
                    data.update(
                        self.redirect_location(value)
                    )
                    continue
            if data.get('match') and not discard_action:
                name_index += 1
                result['rules'].append(data)
        return result