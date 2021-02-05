{% from 'allowed_states.map.jinja' import allowed_states %}
{% if sls in allowed_states %}

# Firewall Magic for the grid
{% from 'firewall/map.jinja' import hostgroups with context %}
{% from 'firewall/map.jinja' import assigned_hostgroups with context %}

create_sysconfig_iptables:
  file.touch:
    - name: /etc/sysconfig/iptables
    - makedirs: True
    - unless: 'ls /etc/sysconfig/iptables'

# Quick Fix for Docker being difficult
iptables_fix_docker:
  iptables.chain_present:
    - name: DOCKER-USER
    - table: filter

# Create the chain for logging
iptables_LOGGING_chain:
  iptables.chain_present:
    - name: LOGGING
    - table: filter
    - family: ipv4

insert_blockreplace_start_and_end:
  cmd.run:
    - name: "LN=$(egrep -n 'filter|COMMIT' /etc/sysconfig/iptables | grep -A1 filter | grep COMMIT | awk -F: {'print $1'}) && sed -i \"$LN i# END SALT BLOCKREPLACE ZONE\" /etc/sysconfig/iptables && sed -i  \"$LN i# START SALT BLOCKREPLACE ZONE\" /etc/sysconfig/iptables"
    - unless: grep "START SALT BLOCKREPLACE ZONE" /etc/sysconfig/iptables

# Add the Forward Rule since Docker ripped it out
iptables_fix_fwd:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A FORWARD -j DOCKER-USER"
    - require_in:
      - file: iptables_file

# Allow related/established sessions
iptables_allow_established:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    - require_in:
      - file: iptables_file

# I like pings
iptables_allow_pings:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A INPUT -p icmp -j ACCEPT"
    - require_in:
      - file: iptables_file

iptables_LOGGING_limit:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: '-A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-dropped: "'
    - require_in:
      - file: iptables_file

# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_log_input_drops:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A INPUT -j LOGGING"
    - require_in:
      - file: iptables_file

# Enable global DOCKER-USER block rule
enable_docker_user_fw_policy:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A DOCKER-USER ! -i docker0 -o docker0 -j LOGGING"
    - require_in:
      - file: iptables_file

enable_docker_user_established:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A DOCKER-USER ! -i docker0 -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    - require_in:
      - file: iptables_file

{% set count = namespace(value=0) %}
{% for chain, hg in assigned_hostgroups.chain.items() %}
  {% for hostgroup, portgroups in assigned_hostgroups.chain[chain].hostgroups.items() %}
    {% for action in ['insert'] %}
      {% if hostgroups[hostgroup].ips[action] %}
        {% for ip in hostgroups[hostgroup].ips[action] %}
          {% for portgroup in portgroups.portgroups %}
            {% for proto, ports in portgroup.items() %}
              {% for port in ports %}
                {% set count.value = count.value + 1 %}

{{action}}_{{chain}}_{{hostgroup}}_{{ip}}_{{port}}_{{proto}}_{{count.value}}:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A {{chain}} -s {{ip}} -p {{proto}} -m {{proto}} --dport {{port}} -j ACCEPT"
    - require_in:
      - file: iptables_file

              {% endfor %}
            {% endfor %}
          {% endfor %}
        {% endfor %}
      {% endif %}
    {% endfor %}
  {% endfor %}
{% endfor %}

# Make the input policy send stuff that doesn't match to be logged and dropped
iptables_drop_all_the_things_accumulator:
  file.accumulated:
    - filename: /etc/sysconfig/iptables
    - text: "-A LOGGING -j DROP"
    - require_in:
      - file: iptables_file

iptables_file:
  file.blockreplace:
    - name: /etc/sysconfig/iptables
    - marker_start: "# START SALT BLOCKREPLACE ZONE"
    - marker_end: "# END SALT BLOCKREPLACE ZONE"

flush_iptables:
  iptables.flush:
    - table: filter
    - family: ipv4
    - onchanges:
      - file: iptables_file

restore_iptables:
  cmd.run:
    - name: "iptables-restore < /etc/sysconfig/iptables"
    - onchanges:
      - file: iptables_file

save_iptables:
  cmd.run:
    - name: "iptables-save > /etc/sysconfig/iptables"
    - onchanges:
      - file: iptables_file

{% else %}

{{sls}}_state_not_allowed:
  test.fail_without_changes:
    - name: {{sls}}_state_not_allowed

{% endif %}