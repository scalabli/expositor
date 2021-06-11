import quo
import shodan

from shodan.cli.helpers import get_api_key, humanize_api_plan


@quo.tether()
def org():
    """Manage your organization's access to Shodan"""
    pass


@org.command()
@quo.option('--silent', help="Don't send a notification to the user", default=False, is_flag=True)
@quo.argument('user', metavar='<username or email>')
def add(silent, user):
    """Add a new member"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        api.org.add_member(user, notify=not silent)
    except shodan.APIError as e:
        raise quo.QuoException(e.value)

    quo.flair('Successfully added the new member', fg='green')


@org.command()
def info():
    """Show an overview of the organization"""
    key = get_api_key()
    api = shodan.Shodan(key)
    try:
        organization = api.org.info()
    except shodan.APIError as e:
        raise quo.QuoException(e.value)

    quo.flair(organization['name'], fg='cyan')
    quo.flair('Access Level: ', nl=False, dim=True)
    quo.flair(humanize_api_plan(organization['upgrade_type']), fg='magenta')

    if organization['domains']:
        quo.flair('Authorized Domains: ', nl=False, dim=True)
        quo.echo(', '.join(organization['domains']))

    quo.echo('')
    quo.flair('Administrators:', dim=True)

    for admin in organization['admins']:
        quo.echo(u' > {:30}\t{:30}'.format(
            quo.style(admin['username'], fg='yellow'),
            admin['email'])
        )

    quo.echo('')
    if organization['members']:
        quo.flair('Members:', dim=True)
        for member in organization['members']:
            quo.echo(u' > {:30}\t{:30}'.format(
                quo.style(member['username'], fg='yellow'),
                member['email'])
            )
    else:
        quo.flair('No members yet', dim=True)


@org.command()
@quo.argument('user', metavar='<username or email>')
def remove(user):
    """Remove and downgrade a member"""
    key = get_api_key()
    api = shodan.Shodan(key)

    try:
        api.org.remove_member(user)
    except shodan.APIError as e:
        raise quo.QuoException(e.value)

    quo.flair('Successfully removed the member', fg='green')
