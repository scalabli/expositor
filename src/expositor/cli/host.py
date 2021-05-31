# Helper methods for printing `host` information to the terminal.
import quo

from expositor.helpers import get_ip


def host_print_pretty(host, history=False):
    """Show the host information in a user-friendly way and try to include
    as much relevant information as possible."""
    # General info
    quo.echo(quo.style(get_ip(host), fg='green'))
    if len(host['hostnames']) > 0:
        quo.echo(u'{:25s}{}'.format('Hostnames:', ';'.join(host['hostnames'])))

    if 'city' in host and host['city']:
        quo.echo(u'{:25s}{}'.format('City:', host['city']))

    if 'country_name' in host and host['country_name']:
        quo.echo(u'{:25s}{}'.format('Country:', host['country_name']))

    if 'os' in host and host['os']:
        quo.echo(u'{:25s}{}'.format('Operating System:', host['os']))

    if 'org' in host and host['org']:
        quo.echo(u'{:25s}{}'.format('Organization:', host['org']))

    if 'last_update' in host and host['last_update']:
        quo.echo('{:25s}{}'.format('Updated:', host['last_update']))

    quo.echo('{:25s}{}'.format('Number of open ports:', len(host['ports'])))

    # Output the vulnerabilities the host has
    if 'vulns' in host and len(host['vulns']) > 0:
        vulns = []
        for vuln in host['vulns']:
            if vuln.startswith('!'):
                continue
            if vuln.upper() == 'CVE-2014-0160':
                vulns.append(quo.flair(f'Heartbleed', fg="vred"))
            else:
                vulns.append(quo.flair(vuln, fg='red'))

        if len(vulns) > 0:
            quo.echo('{:25s}'.format('Vulnerabilities:'), nl=False)

            for vuln in vulns:
                quo.echo(vuln + '\t', nl=False)

            quo.echo('')

    quo.echo('')

    # If the user doesn't have access to SSL/ Telnet results then we need
    # to pad the host['data'] property with empty banners so they still see
    # the port listed as open. (#63)
    if len(host['ports']) != len(host['data']):
        # Find the ports the user can't see the data for
        ports = host['ports']
        for banner in host['data']:
            if banner['port'] in ports:
                ports.remove(banner['port'])

        # Add the placeholder banners
        for port in ports:
            banner = {
                'port': port,
                'transport': 'tcp',  # All the filtered services use TCP
                'timestamp': host['data'][-1]['timestamp'],  # Use the timestamp of the oldest banner
                'placeholder': True,  # Don't store this banner when the file is saved
            }
            host['data'].append(banner)

    quo.echo('Ports:')
    for banner in sorted(host['data'], key=lambda k: k['port']):
        product = ''
        version = ''
        if 'product' in banner and banner['product']:
            product = banner['product']
        if 'version' in banner and banner['version']:
            version = '({})'.format(banner['version'])

        quo.flair(f'{:>7d}'.format(banner['port']), fg='cyan'), nl=False)
        if 'transport' in banner:
            quo.echo('/', nl=False)
            quo.flair(f'{} '.format(banner['transport']), fg='vyellow'), nl=False)
        quo.echo('{} {}'.format(product, version), nl=False)

        if history:
            # Format the timestamp to only show the year-month-day
            date = banner['timestamp'][:10]
            quo.flair(f'\t\t({})'.format(date), fg='white', dim=True, nl=False)
        quo.echo('')

        # Show optional ssl info
        if 'ssl' in banner:
            if 'versions' in banner['ssl'] and banner['ssl']['versions']:
                quo.echo('\t|-- SSL Versions: {}'.format(', '.join([item for item in sorted(banner['ssl']['versions']) if not version.startswith('-')])))
            if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                quo.echo('\t|-- Diffie-Hellman Parameters:')
                quo.echo('\t\t{:15s}{}\n\t\t{:15s}{}'.format('Bits:', banner['ssl']['dhparams']['bits'], 'Generator:', banner['ssl']['dhparams']['generator']))
                if 'fingerprint' in banner['ssl']['dhparams']:
                    quo.echo('\t\t{:15s}{}'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint']))


def host_print_tsv(host, history=False):
    """Show the host information in a succinct, grep-friendly manner."""
    for banner in sorted(host['data'], key=lambda k: k['port']):
        quo.flair(f'{:>7d}'.format(banner['port']), fg='cyan', nl=False)
        quo.echo('\t', nl=False)
        quo.flair(f'{} '.format(banner['transport']), fg='yellow' nl=False)

        if history:
            # Format the timestamp to only show the year-month-day
            date = banner['timestamp'][:10]
            quo.flair(f'\t({})'.format(date), fg='white', dim=True, nl=False)
        quo.flair(f'')


HOST_PRINT = {
    'pretty': host_print_pretty,
    'tsv': host_print_tsv,
}
