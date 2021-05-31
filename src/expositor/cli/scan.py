import quo
import collections
import datetime
import shodan
import shodan.helpers as helpers
import socket
import threading
import time

from shodan.cli.helpers import get_api_key, async_spinner
from shodan.cli.settings import COLORIZE_FIELDS


@quo.group()
def scan():
    """Scan an IP/ netblock using Shodan."""
    pass


@scan.command(name='list')
def scan_list():
    """Show recently launched scans"""
    key = get_api_key()

    # Get the list
    api = shodan.Shodan(key)
    try:
        scans = api.scans()
    except shodan.APIError as e:
        raise quo.QuoException(e.value)

    if len(scans) > 0:
        quo.echo(u'# {} Scans Total - Showing 10 most recent scans:'.format(scans['total']))
        quo.echo(u'# {:20} {:<15} {:<10} {:<15s}'.format('Scan ID', 'Status', 'Size', 'Timestamp'))
        # quo.echo('#' * 65)
        for scan in scans['matches'][:10]:
            quo.echo(
                u'{:31} {:<24} {:<10} {:<15s}'.format(
                    quo.style(scan['id'], fg='yellow'),
                    quo.style(scan['status'], fg='cyan'),
                    scan['size'],
                    scan['created']
                )
            )
    else:
        quo.echo("You haven't yet launched any scans.")


@scan.command(name='internet')
@quo.option('--quiet', help='Disable the printing of information to the screen.', default=False, is_flag=True)
@quo.argument('port', type=int)
@quo.argument('protocol', type=str)
def scan_internet(quiet, port, protocol):
    """Scan the Internet for a specific port and protocol using the Shodan infrastructure."""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        # Submit the request to Shodan
        quo.echo('Submitting Internet scan to Shodan...', nl=False)
        scan = api.scan_internet(port, protocol)
        quo.echo('Done')

        # If the requested port is part of the regular Shodan crawling, then
        # we don't know when the scan is done so lets return immediately and
        # let the user decide when to stop waiting for further results.
        official_ports = api.ports()
        if port in official_ports:
            quo.echo('The requested port is already indexed by Shodan. A new scan for the port has been launched, please subscribe to the real-time stream for results.')
        else:
            # Create the output file
            filename = '{0}-{1}.json.gz'.format(port, protocol)
            counter = 0
            with helpers.open_file(filename, 'w') as fout:
                quo.echo('Saving results to file: {0}'.format(filename))

                # Start listening for results
                done = False

                # Keep listening for results until the scan is done
                quo.echo('Waiting for data, please stand by...')
                while not done:
                    try:
                        for banner in api.stream.ports([port], timeout=90):
                            counter += 1
                            helpers.write_banner(fout, banner)

                            if not quiet:
                                quo.echo('{0:<40} {1:<20} {2}'.format(
                                    quo.style(helpers.get_ip(banner), fg=COLORIZE_FIELDS['ip_str']),
                                    quo.style(str(banner['port']), fg=COLORIZE_FIELDS['port']),
                                    ';'.join(banner['hostnames']))
                                )
                    except shodan.APIError:
                        # We stop waiting for results if the scan has been processed by the crawlers and
                        # there haven't been new results in a while
                        if done:
                            break

                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except socket.timeout:
                        # We stop waiting for results if the scan has been processed by the crawlers and
                        # there haven't been new results in a while
                        if done:
                            break

                        scan = api.scan_status(scan['id'])
                        if scan['status'] == 'DONE':
                            done = True
                    except Exception as e:
                        raise quo.QuoException(repr(e))
            quo.echo('Scan finished: {0} devices found'.format(counter))
    except shodan.APIError as e:
        raise quo.QuoException(e.value)


@scan.command(name='protocols')
def scan_protocols():
    """List the protocols that you can scan with using Shodan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        protocols = api.protocols()

        for name, description in iter(protocols.items()):
            quo.echo(quo.style('{0:<30}'.format(name), fg='cyan') + description)
    except shodan.APIError as e:
        raise quo.QuoException(e.value)


@scan.command(name='submit')
@quo.option('--wait', help='How long to wait for results to come back. If this is set to "0" or below return immediately.', default=20, type=int)
@quo.option('--filename', help='Save the results in the given file.', default='', type=str)
@quo.option('--force', default=False, is_flag=True)
@quo.option('--verbose', default=False, is_flag=True)
@quo.argument('netblocks', metavar='<ip address>', nargs=-1)
def scan_submit(wait, filename, force, verbose, netblocks):
    """Scan an IP/ netblock using Shodan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    alert = None

    # Submit the IPs for scanning
    try:
        # Submit the scan
        scan = api.scan(netblocks, force=force)

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')

        quo.echo('')
        quo.echo('Starting Shodan scan at {} - {} scan credits left'.format(now, scan['credits_left']))

        if verbose:
            quo.echo('# Scan ID: {}'.format(scan['id']))

        # Return immediately
        if wait <= 0:
            quo.echo('Exiting now, not waiting for results. Use the API or website to retrieve the results of the scan.')
        else:
            # Setup an alert to wait for responses
            alert = api.create_alert('Scan: {}'.format(', '.join(netblocks)), netblocks)

            # Create the output file if necessary
            filename = filename.strip()
            fout = None
            if filename != '':
                # Add the appropriate extension if it's not there atm
                if not filename.endswith('.json.gz'):
                    filename += '.json.gz'
                fout = helpers.open_file(filename, 'w')

            # Start a spinner
            finished_event = threading.Event()
            progress_bar_thread = threading.Thread(target=async_spinner, args=(finished_event,))
            progress_bar_thread.start()

            # Now wait a few seconds for items to get returned
            hosts = collections.defaultdict(dict)
            done = False
            scan_start = time.time()
            cache = {}
            while not done:
                try:
                    for banner in api.stream.alert(aid=alert['id'], timeout=wait):
                        ip = banner.get('ip', banner.get('ipv6', None))
                        if not ip:
                            continue

                        # Don't show duplicate banners
                        cache_key = '{}:{}'.format(ip, banner['port'])
                        if cache_key not in cache:
                            hosts[helpers.get_ip(banner)][banner['port']] = banner
                            cache[cache_key] = True

                        # If we've grabbed data for more than 60 seconds it might just be a busy network and we should move on
                        if time.time() - scan_start >= 60:
                            scan = api.scan_status(scan['id'])

                            if verbose:
                                quo.echo('# Scan status: {}'.format(scan['status']))

                            if scan['status'] == 'DONE':
                                done = True
                                break

                except shodan.APIError:
                    # If the connection timed out before the timeout, that means the streaming server
                    # that the user tried to reach is down. In that case, lets wait briefly and try
                    # to connect again!
                    if (time.time() - scan_start) < wait:
                        time.sleep(0.5)
                        continue

                    # Exit if the scan was flagged as done somehow
                    if done:
                        break

                    scan = api.scan_status(scan['id'])
                    if scan['status'] == 'DONE':
                        done = True

                    if verbose:
                        quo.echo('# Scan status: {}'.format(scan['status']))
                except socket.timeout:
                    # If the connection timed out before the timeout, that means the streaming server
                    # that the user tried to reach is down. In that case, lets wait a second and try
                    # to connect again!
                    if (time.time() - scan_start) < wait:
                        continue

                    done = True
                except Exception as e:
                    finished_event.set()
                    progress_bar_thread.join()
                    raise quo.QuoException(repr(e))

            finished_event.set()
            progress_bar_thread.join()

            def print_field(name, value):
                quo.echo('  {:25s}{}'.format(name, value))

            def print_banner(banner):
                quo.echo('    {:20s}'.format(quo.style(str(banner['port']), fg='green') + '/' + banner['transport']), nl=False)

                if 'product' in banner:
                    quo.echo(banner['product'], nl=False)

                    if 'version' in banner:
                        quo.echo(' ({})'.format(banner['version']), nl=False)

                quo.echo('')

                # Show optional ssl info
                if 'ssl' in banner:
                    if 'versions' in banner['ssl']:
                        # Only print SSL versions if they were successfully tested
                        versions = [version for version in sorted(banner['ssl']['versions']) if not version.startswith('-')]
                        if len(versions) > 0:
                            quo.echo('    |-- SSL Versions: {}'.format(', '.join(versions)))
                    if 'dhparams' in banner['ssl'] and banner['ssl']['dhparams']:
                        quo.echo('    |-- Diffie-Hellman Parameters:')
                        quo.echo('        {:15s}{}\n        {:15s}{}'.format('Bits:', banner['ssl']['dhparams']['bits'], 'Generator:', banner['ssl']['dhparams']['generator']))
                        if 'fingerprint' in banner['ssl']['dhparams']:
                            quo.echo('        {:15s}{}'.format('Fingerprint:', banner['ssl']['dhparams']['fingerprint']))

            if hosts:
                # Remove the remaining spinner character
                quo.echo('\b ')

                for ip in sorted(hosts):
                    host = next(iter(hosts[ip].items()))[1]

                    quo.echo(quo.style(ip, fg='cyan'), nl=False)
                    if 'hostnames' in host and host['hostnames']:
                        quo.echo(' ({})'.format(', '.join(host['hostnames'])), nl=False)
                    quo.echo('')

                    if 'location' in host and 'country_name' in host['location'] and host['location']['country_name']:
                        print_field('Country', host['location']['country_name'])

                        if 'city' in host['location'] and host['location']['city']:
                            print_field('City', host['location']['city'])
                    if 'org' in host and host['org']:
                        print_field('Organization', host['org'])
                    if 'os' in host and host['os']:
                        print_field('Operating System', host['os'])
                    quo.echo('')

                    # Output the vulnerabilities the host has
                    if 'vulns' in host and len(host['vulns']) > 0:
                        vulns = []
                        for vuln in host['vulns']:
                            if vuln.startswith('!'):
                                continue
                            if vuln.upper() == 'CVE-2014-0160':
                                vulns.append(quo.style('Heartbleed', fg='red'))
                            else:
                                vulns.append(quo.style(vuln, fg='red'))

                        if len(vulns) > 0:
                            quo.echo('  {:25s}'.format('Vulnerabilities:'), nl=False)

                            for vuln in vulns:
                                quo.echo(vuln + '\t', nl=False)

                            quo.echo('')

                    # Print all the open ports:
                    quo.echo('  Open Ports:')
                    for port in sorted(hosts[ip]):
                        print_banner(hosts[ip][port])

                        # Save the banner in a file if necessary
                        if fout:
                            helpers.write_banner(fout, hosts[ip][port])

                    quo.echo('')
            else:
                # Prepend a \b to remove the spinner
                quo.echo('\bNo open ports found or the host has been recently crawled and cant get scanned again so soon.')
    except shodan.APIError as e:
        raise quo.QuoException(e.value)
    finally:
        # Remove any alert
        if alert:
            api.delete_alert(alert['id'])


@scan.command(name='status')
@quo.argument('scan_id', type=str)
def scan_status(scan_id):
    """Check the status of an on-demand scan."""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        scan = api.scan_status(scan_id)
        quo.echo(scan['status'])
    except shodan.APIError as e:
        raise quo.QuoException(e.value)
